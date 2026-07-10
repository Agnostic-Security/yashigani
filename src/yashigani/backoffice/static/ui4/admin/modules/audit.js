// Yashigani 4.0 admin shell — Audit & SIEM module (Governance group).
//
// Surfaces the tamper-evident audit log + the SIEM/sink delivery plane:
//   GET  /admin/audit/search          → filtered audit-log search (R19/R20)
//   GET  /admin/audit/facets          → verdict + source-type filter vocab
//   GET  /admin/audit/export          → filtered NDJSON/CSV (download)
//   GET  /admin/audit/export/raw      → unfiltered raw NDJSON/CSV (GAP AU-01)
//   GET  /admin/audit/sinks           → sink registry + last-write (GAP AS-01)
//   GET  /admin/audit/siem            → named SIEM targets (GAP AU-10..13)
//   POST /admin/audit/siem            → add target
//   DELETE /admin/audit/siem/{name}   → remove target
//   POST /admin/audit/siem/{name}/test→ send synthetic test event
//   GET  /admin/audit/masking/scope   → audit masking config (GAP AU-02)
//
// AUDIT-CHAIN (RISK-104): every audit record is appended to a SHA-384 hash-chain
// with a daily ECDSA-signed Merkle checkpoint. This module surfaces the chain
// trust statement + the per-row chain linkage (record_hash / prev_hash) when the
// search rows carry them, so an operator can SEE the tamper-evidence.
//
// TRUSTED-CHROME: audit rows are server-authored JSON but carry user-influenced
// fields (agent names, free-text, paths). EVERY field is rendered through Lit
// auto-escape (textContent via ys-table / ${value}) — never the §3 markdown sink
// and never innerHTML. An XSS payload in any audit field is therefore inert.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

// Governance actions that MUST be in the hash-chain (RISK-104). Used by the
// coverage panel + as one-click audit-search filters so an operator can confirm
// each governance mutation is actually being recorded.
const GOVERNANCE_EVENT_TYPES = [
  { event_type: 'OPA_ASSISTANT_SUGGESTION_APPLIED', label: 'OPA-assistant apply (AI Rego)' },
  { event_type: 'OPA_ASSISTANT_SUGGESTION_GENERATED', label: 'OPA-assistant suggest' },
  { event_type: 'OPA_ASSISTANT_SUGGESTION_REJECTED', label: 'OPA-assistant reject' },
  { event_type: 'POLICY_PROMOTED', label: 'Policy promote' },
  { event_type: 'SENSITIVITY_PATTERN_CREATED', label: 'Sensitivity pattern create' },
  { event_type: 'CONFIG_CHANGED', label: 'Config change (alerts/PII/budget)' },
];

export class YsAdminAudit extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _facets: { state: true },
    _rows: { state: true },
    _scanned: { state: true },
    _filters: { state: true },
    _sinks: { state: true },
    _targets: { state: true },
    _masking: { state: true },
    _newTarget: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._facets = { verdicts: [], source_types: [] };
    this._rows = [];
    this._scanned = 0;
    this._filters = { event_type: '', verdict: '', source_type: '', user: '', free_text: '', date_from: '', date_to: '' };
    this._sinks = null;
    this._targets = [];
    this._masking = null;
    this._newTarget = { name: '', target_type: 'splunk', url: '', auth_header: 'Authorization', auth_value: '' };
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._loadMeta();
    this._search();
  }

  async _loadMeta() {
    const [facets, sinks, targets, masking] = await Promise.all([
      this.api.get('/admin/audit/facets'),
      this.api.get('/admin/audit/sinks'),
      this.api.get('/admin/audit/siem'),
      this.api.get('/admin/audit/masking/scope'),
    ]);
    this._facets = facets || { verdicts: [], source_types: [] };
    this._sinks = (sinks && sinks.sinks) || null;
    this._targets = (targets && Array.isArray(targets.siem_targets)) ? targets.siem_targets : [];
    this._masking = masking || null;
  }

  _qs() {
    const f = this._filters;
    const p = new URLSearchParams();
    for (const k of Object.keys(f)) { if (f[k]) p.set(k, f[k]); }
    return p.toString();
  }

  async _search() {
    this._loading = true;
    const qs = this._qs();
    const res = await this.api.get(`/admin/audit/search${qs ? '?' + qs : ''}`);
    this._rows = (res && Array.isArray(res.rows)) ? res.rows : [];
    this._scanned = (res && res.total_scanned) || 0;
    this._loading = false;
  }

  _setFilter(k, v) { this._filters = { ...this._filters, [k]: v }; }

  _filterByEvent(eventType) {
    this._filters = { ...this._filters, event_type: eventType };
    this._search();
  }

  _export(raw, fmt) {
    // Downloads stream from the server; window.open keeps the audited session
    // cookie (same-origin). raw → unfiltered dump (AU-01); else filtered (AU-16).
    const base = raw ? '/admin/audit/export/raw' : '/admin/audit/export';
    const p = raw ? new URLSearchParams() : new URLSearchParams(this._qs());
    p.set(raw ? 'output_format' : 'output_format', fmt);
    window.open(`${base}?${p.toString()}`, '_blank', 'noopener');
  }

  async _addTarget() {
    const t = this._newTarget;
    if (!t.name || !t.url) { this.app && this.app.toast('Name and URL are required.', 'error'); return; }
    const res = await this.api.mutate('/admin/audit/siem', { method: 'POST', body: t });
    if (res.ok) {
      this.app && this.app.toast('SIEM target added.', 'success');
      this._newTarget = { name: '', target_type: 'splunk', url: '', auth_header: 'Authorization', auth_value: '' };
      this._loadMeta();
    } else {
      this.app && this.app.toast(res.error ? res.error.message : 'Failed to add target.', 'error');
    }
  }

  async _removeTarget(name) {
    const res = await this.api.mutate(`/admin/audit/siem/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (res.ok) { this.app && this.app.toast('Target removed.', 'success'); this._loadMeta(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  async _testTarget(name) {
    const res = await this.api.mutate(`/admin/audit/siem/${encodeURIComponent(name)}/test`, { method: 'POST' });
    this.app && this.app.toast(res.ok ? 'Test event sent.' : (res.error ? res.error.message : 'Test failed.'), res.ok ? 'success' : 'error');
  }

  _renderChainStatus() {
    const lastWrite = this._sinks && this._sinks.file ? this._sinks.file.last_write : null;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          <span class="ys-semaphore ys-semaphore--ok" title="hash-chain active"></span>
          Audit integrity — tamper-evident hash-chain
        </div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Every audit record is appended to a SHA-384 hash-chain and sealed by a
            daily ECDSA-signed Merkle checkpoint (RISK-104). Records carry
            <code>record_hash</code>/<code>prev_hash</code> linkage shown per row below.
          </div>
          <ul class="ys-alert-list">
            <li class="ys-alert-item">
              <span class="ys-alert-label">File sink last write</span>
              <span class="ys-alert-count">${lastWrite || '—'}</span>
            </li>
            <li class="ys-alert-item">
              <span class="ys-alert-label">Registered SIEM targets</span>
              <span class="ys-alert-count">${this._targets.length}</span>
            </li>
          </ul>
        </div>
      </div>`;
  }

  _renderGovernanceCoverage() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Governance-action audit coverage (RISK-104)</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            These governance mutations must appear in the chain. Click to filter the
            log and confirm each is recorded; an empty result on a recent action is a
            coverage gap to flag.
          </div>
          <ul class="ys-alert-list">
            ${GOVERNANCE_EVENT_TYPES.map((g) => html`
              <li class="ys-alert-item">
                <span class="ys-alert-label">${g.label}</span>
                <button class="ys-btn ys-btn-ghost" @click=${() => this._filterByEvent(g.event_type)}>
                  Show in log
                </button>
              </li>`)}
          </ul>
        </div>
      </div>`;
  }

  _renderSearch() {
    const verdicts = Array.isArray(this._facets.verdicts) ? this._facets.verdicts : [];
    const sources = Array.isArray(this._facets.source_types) ? this._facets.source_types : [];
    const f = this._filters;
    const columns = [
      { key: 'timestamp', label: 'Time', sortable: true },
      { key: 'event_type', label: 'Event', sortable: true },
      { key: 'actor', label: 'Actor', render: (r) => r.admin_account || r.user_handle || r.agent_id || '—' },
      { key: 'verdict', label: 'Verdict', render: (r) => r.verdict || r.action || '—' },
      { key: 'chain', label: 'Chain', render: (r) => (r.record_hash ? String(r.record_hash).slice(0, 10) + '…' : '—') },
      { key: 'detail', label: 'Detail', render: (r) => r.message || r.reason || r.path || '' },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Audit log search</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Event type</label>
            <input class="ys-input" .value=${f.event_type}
                   @input=${(e) => this._setFilter('event_type', e.target.value)}
                   placeholder="e.g. ADMIN_LOGIN">
          </div>
          <div class="ys-admin-2col">
            <div class="ys-field">
              <label class="ys-label">Verdict</label>
              <select class="ys-select" .value=${f.verdict}
                      @change=${(e) => this._setFilter('verdict', e.target.value)}>
                ${verdicts.map((v) => html`<option value=${v.value}>${v.label}</option>`)}
              </select>
            </div>
            <div class="ys-field">
              <label class="ys-label">Source</label>
              <select class="ys-select" .value=${f.source_type}
                      @change=${(e) => this._setFilter('source_type', e.target.value)}>
                ${sources.map((s) => html`<option value=${s.value}>${s.label}</option>`)}
              </select>
            </div>
          </div>
          <div class="ys-field">
            <label class="ys-label">Actor (user / admin)</label>
            <input class="ys-input" .value=${f.user} @input=${(e) => this._setFilter('user', e.target.value)}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Free text</label>
            <input class="ys-input" .value=${f.free_text} @input=${(e) => this._setFilter('free_text', e.target.value)}>
          </div>
          <button class="ys-btn" @click=${() => this._search()}>Search</button>
          <button class="ys-btn ys-btn-ghost" @click=${() => this._export(false, 'json')}>Export (filtered NDJSON)</button>
          <button class="ys-btn ys-btn-ghost" @click=${() => this._export(false, 'csv')}>Export CSV</button>
          <button class="ys-btn ys-btn-ghost" @click=${() => this._export(true, 'ndjson')}>Raw export</button>
        </div>
      </div>
      <div class="ys-panel">
        <div class="ys-panel-header">Results${this._scanned ? ` — scanned ${this._scanned}` : ''}</div>
        <div class="ys-panel-body">
          ${this._loading
            ? html`<div class="ys-txt-note">Searching…</div>`
            : html`<ys-table id="audit-results" .columns=${columns} .rows=${this._rows}
                     emptyText="No matching audit records."></ys-table>`}
        </div>
      </div>`;
  }

  _renderSiem() {
    const t = this._newTarget;
    const cols = [
      { key: 'name', label: 'Name', sortable: true },
      { key: 'target_type', label: 'Type' },
      { key: 'url', label: 'Endpoint' },
      { key: 'enabled', label: 'Enabled', render: (r) => (r.enabled ? 'yes' : 'no') },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">SIEM targets</div>
        <div class="ys-panel-body">
          <ys-table .columns=${cols} .rows=${this._targets} emptyText="No SIEM targets configured."></ys-table>
          ${this._targets.map((tg) => html`
            <div class="ys-svc-card">
              <div class="ys-svc-meta"><div class="ys-svc-name">${tg.name}</div>
                <div class="ys-txt-note">${tg.url}</div></div>
              <button class="ys-btn ys-btn-ghost" @click=${() => this._testTarget(tg.name)}>Test</button>
              <button class="ys-btn ys-btn-danger" @click=${() => this._removeTarget(tg.name)}>Remove</button>
            </div>`)}
          <div class="ys-panel-header">Add target</div>
          <div class="ys-field"><label class="ys-label">Name</label>
            <input class="ys-input" .value=${t.name} @input=${(e) => { this._newTarget = { ...t, name: e.target.value }; }}></div>
          <div class="ys-field"><label class="ys-label">Type</label>
            <select class="ys-select" .value=${t.target_type}
                    @change=${(e) => { this._newTarget = { ...t, target_type: e.target.value }; }}>
              <option value="splunk">Splunk</option>
              <option value="elasticsearch">Elasticsearch</option>
              <option value="wazuh">Wazuh</option>
              <option value="generic">Generic webhook</option>
            </select></div>
          <div class="ys-field"><label class="ys-label">Endpoint URL</label>
            <input class="ys-input" .value=${t.url} @input=${(e) => { this._newTarget = { ...t, url: e.target.value }; }}></div>
          <div class="ys-field"><label class="ys-label">Auth token (write-only)</label>
            <input class="ys-input" type="password" .value=${t.auth_value}
                   @input=${(e) => { this._newTarget = { ...t, auth_value: e.target.value }; }}></div>
          <button class="ys-btn" id="audit-add-target" @click=${() => this._addTarget()}>Add SIEM target</button>
        </div>
      </div>`;
  }

  render() {
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderChainStatus()}
        <div class="ys-admin-2col">
          ${this._renderGovernanceCoverage()}
          ${this._renderSiem()}
        </div>
        ${this._renderSearch()}
      </div>`;
  }
}

customElements.define('ys-admin-audit', YsAdminAudit);

registerAdminModule({
  id: 'audit',
  label: 'Audit & SIEM',
  icon: '▤',
  order: 30,
  group: 'governance',
  render: (ctx) => html`<ys-admin-audit .api=${ctx.api} .app=${ctx.app}></ys-admin-audit>`,
});
