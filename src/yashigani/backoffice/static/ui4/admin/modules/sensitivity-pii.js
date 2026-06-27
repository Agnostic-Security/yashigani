// Yashigani 4.0 admin shell — Sensitivity & PII module (Governance/Data group).
//
// Data-classification + PII detection config on one page:
//   Sensitivity (sensitivity.py):
//     GET    /admin/sensitivity/status              → pipeline layers active
//     GET    /admin/sensitivity/patterns            → detection patterns
//     POST   /admin/sensitivity/patterns   [STEP-UP]→ add pattern
//     DELETE /admin/sensitivity/patterns/{id}[STEP-UP]
//     GET    /admin/sensitivity/taxonomy            → level labels
//     POST   /admin/sensitivity/taxonomy/{lvl}[STEP-UP]
//     DELETE /admin/sensitivity/taxonomy/{lvl}[STEP-UP]
//     POST   /admin/sensitivity/test                → classify a sample
//     POST   /admin/sensitivity/generate-pattern    → AI-draft a regex
//   PII (pii.py — GAP PII-01..05, dark in 3.x):
//     GET/PUT /admin/pii/config                      → mode + enabled types
//     POST    /admin/pii/test                        → detect (masked output)
//     GET/PUT /admin/pii/cloud-bypass                → cloud bypass toggle
//
// STEP-UP (RISK-103): pattern + taxonomy mutations are StepUpAdminSession; the
// TOTP modal fires transparently through ctx.api.mutate on the server tag.
//
// SAFE-RENDER: classifier-test echoes the operator's OWN sample back; AI-drafted
// regex is LLM output. Both are bound via Lit text-binding into inputs/<pre>
// (textContent) — never innerHTML, never the markdown sink. XSS-inert.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminSensitivity extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _status: { state: true },
    _patterns: { state: true },
    _taxonomy: { state: true },
    _newPattern: { state: true },
    _sample: { state: true },
    _testResult: { state: true },
    _genResult: { state: true },
    _pii: { state: true },
    _piiBypass: { state: true },
    _piiSample: { state: true },
    _piiResult: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._status = null;
    this._patterns = [];
    this._taxonomy = [];
    this._newPattern = { classification: '1', type: 'regex', pattern: '', description: '' };
    this._sample = '';
    this._testResult = null;
    this._genResult = null;
    this._pii = null;
    this._piiBypass = null;
    this._piiSample = '';
    this._piiResult = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const [status, patterns, taxonomy, pii, bypass] = await Promise.all([
      this.api.get('/admin/sensitivity/status'),
      this.api.get('/admin/sensitivity/patterns'),
      this.api.get('/admin/sensitivity/taxonomy'),
      this.api.get('/admin/pii/config'),
      this.api.get('/admin/pii/cloud-bypass'),
    ]);
    this._status = status || null;
    this._patterns = (patterns && Array.isArray(patterns.patterns)) ? patterns.patterns : [];
    this._taxonomy = (taxonomy && Array.isArray(taxonomy.taxonomy)) ? taxonomy.taxonomy : [];
    this._pii = pii || null;
    this._piiBypass = bypass || null;
    this._loading = false;
  }

  async _addPattern() {
    const p = this._newPattern;
    if (!p.pattern || !p.description) { this.app && this.app.toast('Pattern and description required.', 'error'); return; }
    const res = await this.api.mutate('/admin/sensitivity/patterns', { method: 'POST', body: p });
    if (res.ok) {
      this.app && this.app.toast('Pattern added.', 'success');
      this._newPattern = { classification: '1', type: 'regex', pattern: '', description: '' };
      this._load();
    } else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  async _deletePattern(id) {
    const res = await this.api.mutate(`/admin/sensitivity/patterns/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (res.ok) { this.app && this.app.toast('Pattern deleted.', 'success'); this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  async _testClassify() {
    if (!this._sample) return;
    const res = await this.api.mutate('/admin/sensitivity/test', { method: 'POST', body: { text: this._sample } });
    this._testResult = res.ok ? res.data : { error: res.error ? res.error.message : 'failed' };
  }

  async _generatePattern() {
    if (!this._sample) { this.app && this.app.toast('Enter sample text to derive a pattern from.', 'error'); return; }
    const res = await this.api.mutate('/admin/sensitivity/generate-pattern', { method: 'POST', body: { description: this._sample } });
    this._genResult = res.ok ? res.data : { error: res.error ? res.error.message : 'failed' };
  }

  async _savePii() {
    const body = { mode: this._pii.mode, enabled_types: this._pii.enabled_types || [] };
    const res = await this.api.mutate('/admin/pii/config', { method: 'PUT', body });
    this._toast(res, 'PII config saved.');
  }

  async _toggleBypass(enabled) {
    const res = await this.api.mutate('/admin/pii/cloud-bypass', { method: 'PUT', body: { enabled } });
    if (res.ok) { this._piiBypass = { ...this._piiBypass, cloud_bypass_enabled: enabled }; }
    this._toast(res, `Cloud bypass ${enabled ? 'enabled' : 'disabled'}.`);
  }

  async _testPii() {
    if (!this._piiSample) return;
    const res = await this.api.mutate('/admin/pii/test', { method: 'POST', body: { text: this._piiSample } });
    this._piiResult = res.ok ? res.data : { error: res.error ? res.error.message : 'failed' };
  }

  _toast(res, okMsg) {
    if (!this.app) return;
    this.app.toast(res.ok ? okMsg : (res.error ? res.error.message : 'Failed.'), res.ok ? 'success' : 'error');
  }

  _renderStatus() {
    const s = this._status || {};
    const layer = (on) => html`<span class="ys-semaphore ${on ? 'ys-semaphore--ok' : 'ys-semaphore--degraded'}"></span>`;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Classification pipeline</div>
        <div class="ys-panel-body">
          <ul class="ys-alert-list">
            <li class="ys-alert-item">${layer(true)}<span class="ys-alert-label">Regex</span><span class="ys-alert-count">always</span></li>
            <li class="ys-alert-item">${layer(s.classifier_available)}<span class="ys-alert-label">Classifier (sklearn)</span><span class="ys-alert-count">${s.classifier_available ? 'on' : 'off'}</span></li>
            <li class="ys-alert-item">${layer(s.ollama_available)}<span class="ys-alert-label">LLM (Ollama)</span><span class="ys-alert-count">${s.ollama_available ? 'on' : 'off'}</span></li>
            <li class="ys-alert-item"><span class="ys-alert-label">Patterns</span><span class="ys-alert-count">${s.pattern_count ?? this._patterns.length}</span></li>
          </ul>
        </div>
      </div>`;
  }

  _renderPatterns() {
    const np = this._newPattern;
    const cols = [
      { key: 'classification_label', label: 'Class', sortable: true },
      { key: 'type', label: 'Type' },
      { key: 'pattern', label: 'Pattern' },
      { key: 'description', label: 'Description' },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Detection patterns (${this._patterns.length})</div>
        <div class="ys-panel-body">
          <ys-table id="patterns-table" .columns=${cols} .rows=${this._patterns} emptyText="No patterns."></ys-table>
          ${this._patterns.map((p) => html`
            <div class="ys-svc-card">
              <div class="ys-svc-meta"><div class="ys-svc-name">${p.description}</div>
                <div class="ys-txt-note">${p.pattern}</div></div>
              <button class="ys-btn ys-btn-danger" @click=${() => this._deletePattern(p.id)}>Delete</button>
            </div>`)}
          <div class="ys-panel-header">Add pattern</div>
          <div class="ys-field"><label class="ys-label">Classification level</label>
            <select class="ys-select" .value=${np.classification}
              @change=${(e) => { this._newPattern = { ...np, classification: e.target.value }; }}>
              ${[1, 2, 3, 4, 5].map((l) => html`<option value=${String(l)}>Level ${l}</option>`)}
            </select></div>
          <div class="ys-field"><label class="ys-label">Type</label>
            <select class="ys-select" .value=${np.type}
              @change=${(e) => { this._newPattern = { ...np, type: e.target.value }; }}>
              ${['regex', 'keyword', 'classifier', 'ollama'].map((t) => html`<option value=${t}>${t}</option>`)}
            </select></div>
          <div class="ys-field"><label class="ys-label">Pattern</label>
            <input class="ys-input" id="pat-pattern" .value=${np.pattern}
              @input=${(e) => { this._newPattern = { ...np, pattern: e.target.value }; }}></div>
          <div class="ys-field"><label class="ys-label">Description</label>
            <input class="ys-input" .value=${np.description}
              @input=${(e) => { this._newPattern = { ...np, description: e.target.value }; }}></div>
          <button class="ys-btn" id="pat-add" @click=${() => this._addPattern()}>Add pattern</button>
        </div>
      </div>`;
  }

  _renderTester() {
    const r = this._testResult;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Classifier test</div>
        <div class="ys-panel-body">
          <div class="ys-field"><label class="ys-label">Sample text</label>
            <textarea class="ys-textarea" id="sens-sample" .value=${this._sample}
              @input=${(e) => { this._sample = e.target.value; }}></textarea></div>
          <button class="ys-btn" id="sens-test" @click=${() => this._testClassify()}>Classify</button>
          <button class="ys-btn ys-btn-ghost" @click=${() => this._generatePattern()}>AI-draft pattern</button>
          ${r ? html`<pre class="ys-md" id="sens-result">${JSON.stringify(r, null, 2)}</pre>` : nothing}
          ${this._genResult ? html`<pre class="ys-md" id="sens-gen">${JSON.stringify(this._genResult, null, 2)}</pre>` : nothing}
        </div>
      </div>`;
  }

  _renderPii() {
    const pii = this._pii;
    if (!pii) return html`<div class="ys-panel"><div class="ys-panel-header">PII detection</div>
      <div class="ys-panel-body"><div class="ys-txt-note">PII config unavailable.</div></div></div>`;
    const allTypes = Array.isArray(pii.all_types) ? pii.all_types : [];
    const enabled = new Set(pii.enabled_types || []);
    const bypassOn = this._piiBypass && this._piiBypass.cloud_bypass_enabled;
    const r = this._piiResult;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">PII detection (GAP PII-01..05)</div>
        <div class="ys-panel-body">
          <div class="ys-field"><label class="ys-label">Mode</label>
            <select class="ys-select" id="pii-mode" .value=${pii.mode}
              @change=${(e) => { this._pii = { ...pii, mode: e.target.value }; }}>
              ${['log', 'redact', 'block'].map((m) => html`<option value=${m}>${m}</option>`)}
            </select></div>
          <div class="ys-field"><label class="ys-label">Enabled types (empty = all)</label>
            <div class="ys-svc-grid">
              ${allTypes.map((t) => html`
                <label class="ys-svc-card">
                  <input type="checkbox" ?checked=${enabled.has(t)}
                    @change=${(e) => {
                      const s = new Set(this._pii.enabled_types || []);
                      if (e.target.checked) s.add(t); else s.delete(t);
                      this._pii = { ...this._pii, enabled_types: [...s] };
                    }}>
                  <span class="ys-svc-name">${t}</span>
                </label>`)}
            </div></div>
          <button class="ys-btn" id="pii-save" @click=${() => this._savePii()}>Save PII config</button>
          <div class="ys-panel-header">Cloud bypass</div>
          <div class="ys-txt-note">${this._piiBypass ? this._piiBypass.warning : ''}</div>
          <label class="ys-svc-card">
            <input type="checkbox" id="pii-bypass" ?checked=${bypassOn}
              @change=${(e) => this._toggleBypass(e.target.checked)}>
            <span class="ys-svc-name">Skip PII filtering for cloud-routed requests</span>
          </label>
          <div class="ys-panel-header">PII test</div>
          <div class="ys-field"><textarea class="ys-textarea" id="pii-sample" .value=${this._piiSample}
            @input=${(e) => { this._piiSample = e.target.value; }}></textarea></div>
          <button class="ys-btn" id="pii-test" @click=${() => this._testPii()}>Detect</button>
          ${r ? html`<pre class="ys-md" id="pii-result">${JSON.stringify(r, null, 2)}</pre>` : nothing}
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
          ${this._renderStatus()}
          ${this._renderTester()}
        </div>
        ${this._renderPatterns()}
        ${this._renderPii()}
      </div>`;
  }
}

customElements.define('ys-admin-sensitivity', YsAdminSensitivity);

registerAdminModule({
  id: 'sensitivity',
  label: 'Sensitivity & PII',
  icon: '◈',
  order: 50,
  render: (ctx) => html`<ys-admin-sensitivity .api=${ctx.api} .app=${ctx.app}></ys-admin-sensitivity>`,
});
