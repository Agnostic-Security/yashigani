// Yashigani 4.0 admin shell — Alerts & Events module (Governance/Monitoring).
//
//   GET/PUT /admin/alerts/config              → sink webhooks + trigger toggles
//   POST    /admin/alerts/test/{sink_type}    → send a test alert
//   GET/PUT /admin/alerts/budget-threshold    → R17 budget alert (GAP AL-04/05)
//   GET     /admin/alerts/custom              → R18 custom rules (GAP AL-06..10)
//   POST    /admin/alerts/custom              → create rule
//   DELETE  /admin/alerts/custom/{id}         → delete rule
//   GET (SSE) /admin/events/inspection-feed   → live inspection feed (GAP EV-01)
//
// SAFE-RENDER: live inspection events carry user-influenced fields (agent_name,
// tool, reason). Rendered via ys-table (Lit auto-escape / textContent) — never
// innerHTML, never the markdown sink. XSS-inert.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminAlerts extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _config: { state: true },
    _budget: { state: true },
    _custom: { state: true },
    _newRule: { state: true },
    _feed: { state: true },
    _feedOn: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._config = null;
    this._budget = null;
    this._custom = [];
    this._newRule = {
      name: '', description: '', trigger_type: 'budget_threshold',
      condition: { field: 'budget_used_pct', operator: 'gte', threshold: 85 },
      channels: [], enabled: true, cooldown_minutes: 60,
    };
    this._feed = [];
    this._feedOn = false;
    this._es = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  disconnectedCallback() {
    this._stopFeed();
    super.disconnectedCallback();
  }

  async _load() {
    this._loading = true;
    const [cfg, budget, custom] = await Promise.all([
      this.api.get('/admin/alerts/config'),
      this.api.get('/admin/alerts/budget-threshold'),
      this.api.get('/admin/alerts/custom'),
    ]);
    this._config = cfg || {};
    this._budget = budget || { enabled: true, threshold_pct: 85 };
    this._custom = (custom && Array.isArray(custom.custom_alerts)) ? custom.custom_alerts : [];
    this._loading = false;
  }

  _setCfg(k, v) { this._config = { ...this._config, [k]: v }; }

  async _saveConfig() {
    const res = await this.api.mutate('/admin/alerts/config', { method: 'PUT', body: this._config });
    this._toast(res, 'Alert config saved.');
  }

  async _testSink(kind) {
    const res = await this.api.mutate(`/admin/alerts/test/${encodeURIComponent(kind)}`, { method: 'POST' });
    this._toast(res, `Test sent to ${kind}.`);
  }

  async _saveBudget() {
    const body = { enabled: this._budget.enabled, threshold_pct: Number(this._budget.threshold_pct) };
    const res = await this.api.mutate('/admin/alerts/budget-threshold', { method: 'PUT', body });
    this._toast(res, 'Budget-threshold alert saved.');
  }

  async _createRule() {
    const n = this._newRule;
    if (!n.name) { this.app && this.app.toast('Rule name required.', 'error'); return; }
    const body = { ...n, condition: { ...n.condition, threshold: Number(n.condition.threshold) } };
    const res = await this.api.mutate('/admin/alerts/custom', { method: 'POST', body });
    if (res.ok) {
      this.app && this.app.toast('Custom alert created.', 'success');
      this._newRule = { ...n, name: '', description: '' };
      this._load();
    } else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  async _deleteRule(id) {
    const res = await this.api.mutate(`/admin/alerts/custom/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (res.ok) { this.app && this.app.toast('Rule deleted.', 'success'); this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  // Live feed uses EventSource (same-origin, cookie-auth admin session). SSE
  // cannot carry custom headers; the endpoint authenticates by the admin cookie.
  _startFeed() {
    if (this._es) return;
    try {
      this._es = new EventSource('/admin/events/inspection-feed');
      this._feedOn = true;
      this._es.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data);
          this._feed = [ev, ...this._feed].slice(0, 100);
        } catch { /* ignore malformed frame */ }
      };
      this._es.onerror = () => { this.app && this.app.toast('Inspection feed disconnected.', 'error'); this._stopFeed(); };
    } catch {
      this.app && this.app.toast('Inspection feed unavailable.', 'error');
    }
  }

  _stopFeed() {
    if (this._es) { try { this._es.close(); } catch { /* noop */ } this._es = null; }
    this._feedOn = false;
  }

  _toast(res, okMsg) {
    if (!this.app) return;
    this.app.toast(res.ok ? okMsg : (res.error ? res.error.message : 'Failed.'), res.ok ? 'success' : 'error');
  }

  _renderConfig() {
    const c = this._config || {};
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Alert sinks</div>
        <div class="ys-panel-body">
          <div class="ys-field"><label class="ys-label">Slack webhook</label>
            <input class="ys-input" id="al-slack" .value=${c.slack_webhook_url || ''}
              @input=${(e) => this._setCfg('slack_webhook_url', e.target.value)}>
            <button class="ys-btn ys-btn-ghost" @click=${() => this._testSink('slack')}>Test</button></div>
          <div class="ys-field"><label class="ys-label">Teams webhook</label>
            <input class="ys-input" .value=${c.teams_webhook_url || ''}
              @input=${(e) => this._setCfg('teams_webhook_url', e.target.value)}>
            <button class="ys-btn ys-btn-ghost" @click=${() => this._testSink('teams')}>Test</button></div>
          <div class="ys-field"><label class="ys-label">PagerDuty routing key</label>
            <input class="ys-input" .value=${c.pagerduty_routing_key || ''}
              @input=${(e) => this._setCfg('pagerduty_routing_key', e.target.value)}>
            <button class="ys-btn ys-btn-ghost" @click=${() => this._testSink('pagerduty')}>Test</button></div>
          <button class="ys-btn" id="al-save" @click=${() => this._saveConfig()}>Save sinks</button>
        </div>
      </div>`;
  }

  _renderBudget() {
    const b = this._budget || {};
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Budget-threshold alert (R17)</div>
        <div class="ys-panel-body">
          <label class="ys-svc-card">
            <input type="checkbox" id="al-budget-en" ?checked=${b.enabled}
              @change=${(e) => { this._budget = { ...b, enabled: e.target.checked }; }}>
            <span class="ys-svc-name">Enabled</span></label>
          <div class="ys-field"><label class="ys-label">Threshold %</label>
            <input class="ys-input" type="number" min="1" max="99" id="al-budget-pct" .value=${String(b.threshold_pct ?? 85)}
              @input=${(e) => { this._budget = { ...b, threshold_pct: e.target.value }; }}></div>
          <button class="ys-btn" id="al-budget-save" @click=${() => this._saveBudget()}>Save</button>
        </div>
      </div>`;
  }

  _renderCustom() {
    const n = this._newRule;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Custom alert rules (${this._custom.length})</div>
        <div class="ys-panel-body">
          ${this._custom.map((r) => html`
            <div class="ys-svc-card">
              <span class="ys-badge ${r.enabled ? 'ys-badge-green' : 'ys-badge-red'}">${r.enabled ? 'on' : 'off'}</span>
              <div class="ys-svc-meta"><div class="ys-svc-name">${r.name}</div>
                <div class="ys-txt-note">${r.trigger_type} · ${r.condition ? r.condition.field + ' ' + r.condition.operator + ' ' + r.condition.threshold : ''}</div></div>
              <button class="ys-btn ys-btn-danger" @click=${() => this._deleteRule(r.id)}>Delete</button>
            </div>`)}
          <div class="ys-panel-header">Create rule</div>
          <div class="ys-field"><label class="ys-label">Name</label>
            <input class="ys-input" id="al-rule-name" .value=${n.name}
              @input=${(e) => { this._newRule = { ...n, name: e.target.value }; }}></div>
          <div class="ys-field"><label class="ys-label">Trigger</label>
            <select class="ys-select" .value=${n.trigger_type}
              @change=${(e) => { this._newRule = { ...n, trigger_type: e.target.value }; }}>
              ${['budget_threshold', 'budget_exhausted', 'anomaly_score', 'policy_violation', 'login_failure_rate', 'user_session_anomaly', 'custom']
                .map((t) => html`<option value=${t}>${t}</option>`)}
            </select></div>
          <div class="ys-admin-2col">
            <div class="ys-field"><label class="ys-label">Field</label>
              <input class="ys-input" .value=${n.condition.field}
                @input=${(e) => { this._newRule = { ...n, condition: { ...n.condition, field: e.target.value } }; }}></div>
            <div class="ys-field"><label class="ys-label">Operator</label>
              <select class="ys-select" .value=${n.condition.operator}
                @change=${(e) => { this._newRule = { ...n, condition: { ...n.condition, operator: e.target.value } }; }}>
                ${['gte', 'gt', 'lte', 'lt', 'eq', 'neq'].map((o) => html`<option value=${o}>${o}</option>`)}
              </select></div>
          </div>
          <div class="ys-field"><label class="ys-label">Threshold</label>
            <input class="ys-input" type="number" .value=${String(n.condition.threshold)}
              @input=${(e) => { this._newRule = { ...n, condition: { ...n.condition, threshold: e.target.value } }; }}></div>
          <button class="ys-btn" id="al-rule-create" @click=${() => this._createRule()}>Create rule</button>
        </div>
      </div>`;
  }

  _renderFeed() {
    const cols = [
      { key: 'timestamp', label: 'Time' },
      { key: 'agent_name', label: 'Agent', render: (r) => r.agent_name || r.agent_id || '—' },
      { key: 'direction', label: 'Dir' },
      { key: 'tool', label: 'Tool' },
      { key: 'verdict', label: 'Verdict' },
      { key: 'reason', label: 'Reason' },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          <span class="ys-semaphore ${this._feedOn ? 'ys-semaphore--ok' : 'ys-semaphore--p5'}"></span>
          Live inspection feed (EV-01)
        </div>
        <div class="ys-panel-body">
          ${this._feedOn
            ? html`<button class="ys-btn ys-btn-ghost" @click=${() => this._stopFeed()}>Stop</button>`
            : html`<button class="ys-btn" id="feed-start" @click=${() => this._startFeed()}>Connect</button>`}
          <ys-table id="feed-table" .columns=${cols} .rows=${this._feed} emptyText="No events yet."></ys-table>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-admin-2col">
          ${this._renderConfig()}
          ${this._renderBudget()}
        </div>
        ${this._renderCustom()}
        ${this._renderFeed()}
      </div>`;
  }
}

customElements.define('ys-admin-alerts', YsAdminAlerts);

registerAdminModule({
  id: 'alerts',
  label: 'Alerts & Events',
  icon: '◔',
  order: 60,
  render: (ctx) => html`<ys-admin-alerts .api=${ctx.api} .app=${ctx.app}></ys-admin-alerts>`,
});
