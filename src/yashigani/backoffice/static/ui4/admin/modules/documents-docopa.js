// Yashigani 4.0 admin shell — Document data-protection (doc-OPA) module.
//
// The data-protection VERDICT policies (LOG / REDACT / PSEUDONYMIZE / BLOCK) that
// the document-enforcement rego applies to uploaded/egress documents:
//   GET    /admin/documents/status            → feature flag + format/action vocab
//   GET    /admin/documents/policies          → policy matrix (data_class×format×route→action)
//   POST   /admin/documents/policies [STEP-UP]→ add policy (re-pushes OPA)
//   DELETE /admin/documents/policies/{id}[STEP-UP]
//   POST   /admin/documents/inspect           → run a sample doc through REAL OPA
//   GET    /admin/documents/sets              → document sets (k-anonymity scope)
//
// STEP-UP (RISK-103): create/delete are StepUpAdminSession — neutralising
// document enforcement is policy-sensitive, so the TOTP modal fires via
// ctx.api.mutate on the server's step_up_required tag.
//
// Self-describing decision contract: each policy carries policy_id + user_message
// + code so the same layman alert surfaces at every enforcement point.
//
// SAFE-RENDER: the inspect result + user_message are server/operator authored and
// rendered via Lit text-binding (textContent) — never innerHTML / markdown sink.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const ACTION_BADGE = {
  LOG: 'ys-badge-blue',
  REDACT: 'ys-badge-amber',
  PSEUDONYMIZE: 'ys-badge-amber',
  BLOCK: 'ys-badge-red',
};

export class YsAdminDocuments extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _status: { state: true },
    _enforcement: { state: true },
    _policies: { state: true },
    _sets: { state: true },
    _new: { state: true },
    _sample: { state: true },
    _inspectResult: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._status = null;
    this._enforcement = null;
    this._policies = [];
    this._sets = [];
    this._new = {
      data_class: 'PII', format: 'any', route: 'any', action: 'REDACT',
      pseudonymize_mode: 'A', small_set_escalation: true, description: '',
      name: '', policy_id: '', user_message: '', code: '',
    };
    this._sample = '';
    this._inspectResult = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const [status, enforcement, policies, sets] = await Promise.all([
      this.api.get('/admin/documents/status'),
      this.api.get('/admin/documents/enforcement'),
      this.api.get('/admin/documents/policies'),
      this.api.get('/admin/documents/sets'),
    ]);
    this._status = status || null;
    this._enforcement = enforcement || null;
    this._policies = (policies && Array.isArray(policies.policies)) ? policies.policies : [];
    this._sets = (sets && Array.isArray(sets.sets)) ? sets.sets : [];
    this._loading = false;
  }

  async _toggleEnforcement(enabled) {
    const res = await this.api.mutate('/admin/documents/enforcement', { method: 'PUT', body: { enabled } });
    if (res.ok) {
      this._enforcement = { ...this._enforcement, enabled };
      this._status = { ...this._status, enabled };
      this.app && this.app.toast(`Document enforcement ${enabled ? 'enabled' : 'disabled'}.`, 'success');
    } else {
      this.app && this.app.toast(res.error ? res.error.message : 'Toggle failed.', 'error');
    }
  }

  _set(k, v) { this._new = { ...this._new, [k]: v }; }

  async _create() {
    const n = this._new;
    if (!n.description || !n.policy_id || !n.user_message || !n.code) {
      this.app && this.app.toast('description, policy_id, code and user_message are required.', 'error');
      return;
    }
    if (!/^[A-Z][A-Z0-9_]+$/.test(n.code)) {
      this.app && this.app.toast('Code must start with A–Z and contain only uppercase letters, digits, and underscores (e.g. DOCUMENT_BLOCKED).', 'error');
      return;
    }
    const res = await this.api.mutate('/admin/documents/policies', { method: 'POST', body: n });
    if (res.ok) {
      this.app && this.app.toast('Document policy added.', 'success');
      this._new = { ...this._new, description: '', policy_id: '', user_message: '', name: '', code: '' };
      await this._load();
    } else {
      // Map Pydantic field-path errors to friendly messages (DOC-007).
      let msg = res.error ? res.error.message : 'Failed.';
      if (msg && /body\.code|code.*String/.test(msg)) {
        msg = 'Code is invalid — must start with A–Z and contain only uppercase letters, digits, and underscores (e.g. DOCUMENT_BLOCKED).';
      } else if (msg && /body\.policy_id/.test(msg)) {
        msg = 'Policy ID is invalid — use uppercase letters/digits separated by hyphens (e.g. DOC-OP-001).';
      } else if (msg && /document_enforcement_disabled|409/.test(msg)) {
        msg = 'Document enforcement is disabled. Enable it via the toggle above, then retry.';
      }
      this.app && this.app.toast(msg, 'error');
    }
  }

  async _delete(id) {
    const res = await this.api.mutate(`/admin/documents/policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (res.ok) { this.app && this.app.toast('Policy removed.', 'success'); this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  async _inspect() {
    if (!this._sample) return;
    const res = await this.api.mutate('/admin/documents/inspect', {
      method: 'POST', body: { content: this._sample, format: 'txt', route: 'ingress-upload' },
    });
    this._inspectResult = res.ok ? res.data : { error: res.error ? res.error.message : 'failed' };
  }

  _opt(arr, val, set) {
    return html`<select class="ys-select" .value=${val} @change=${(e) => set(e.target.value)}>
      ${arr.map((o) => html`<option value=${o}>${o}</option>`)}</select>`;
  }

  _renderStatus() {
    const s = this._status || {};
    const enabled = this._enforcement ? this._enforcement.enabled : s.enabled;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          <span class="ys-semaphore ${enabled ? 'ys-semaphore--ok' : 'ys-semaphore--degraded'}"></span>
          Document enforcement — ${enabled ? 'enabled' : 'disabled'}
        </div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Verdict spectrum: LOG → REDACT → PSEUDONYMIZE → BLOCK. Supported formats:
            ${(s.supported_formats || []).map((f) => f.ext).join(', ') || '—'}.
            Parked (fail-closed BLOCK): ${(s.parked_formats || []).map((f) => f.ext).join(', ') || '—'}.
          </div>
          <label class="ys-svc-card">
            <input type="checkbox" id="doc-enforcement-toggle"
              ?checked=${enabled}
              @change=${(e) => this._toggleEnforcement(e.target.checked)}>
            <span class="ys-svc-name">Enable document enforcement (step-up required)</span>
          </label>
          ${this._enforcement && this._enforcement.source === 'env' ? html`
            <div class="ys-txt-note">Initial state from environment variable YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED. Toggle overrides for this container lifetime.</div>` : nothing}
        </div>
      </div>`;
  }

  _renderPolicies() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Verdict policies (${this._policies.length})</div>
        <div class="ys-panel-body">
          ${this._policies.length === 0
            ? html`<div class="ys-txt-note">No document policies.</div>`
            : this._policies.map((p) => html`
                <div class="ys-svc-card">
                  <span class="ys-badge ${ACTION_BADGE[p.action] || 'ys-badge-blue'}">${p.action}</span>
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${p.name || p.policy_id || p.id}</div>
                    <div class="ys-txt-note">${p.data_class} · ${p.format} · ${p.route}
                      ${p.action === 'PSEUDONYMIZE' ? `· mode ${p.pseudonymize_mode || 'A'}` : ''}</div>
                    <div class="ys-txt-note">${p.user_message || ''}</div>
                  </div>
                  <button class="ys-btn ys-btn-danger" @click=${() => this._delete(p.policy_id || p.id)}>Delete</button>
                </div>`)}
        </div>
      </div>`;
  }

  _renderCreate() {
    const n = this._new;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Add verdict policy (step-up)</div>
        <div class="ys-panel-body">
          <div class="ys-admin-2col">
            <div class="ys-field"><label class="ys-label">Data class</label>
              ${this._opt(['PII', 'QI', 'PHI', 'PCI', 'SECRET', 'IP_MARKING'], n.data_class, (v) => this._set('data_class', v))}</div>
            <div class="ys-field"><label class="ys-label">Action</label>
              ${this._opt(['LOG', 'REDACT', 'PSEUDONYMIZE', 'BLOCK'], n.action, (v) => this._set('action', v))}</div>
          </div>
          <div class="ys-admin-2col">
            <div class="ys-field"><label class="ys-label">Format</label>
              ${this._opt(['any', 'docx', 'xlsx', 'pptx', 'pdf', 'csv', 'txt'], n.format, (v) => this._set('format', v))}</div>
            <div class="ys-field"><label class="ys-label">Route</label>
              ${this._opt(['any', 'ingress-upload', 'egress-mcp-result', 'json-attachment'], n.route, (v) => this._set('route', v))}</div>
          </div>
          ${n.action === 'PSEUDONYMIZE' ? html`
            <div class="ys-field"><label class="ys-label">Pseudonymise mode</label>
              ${this._opt(['A', 'B'], n.pseudonymize_mode, (v) => this._set('pseudonymize_mode', v))}</div>` : nothing}
          <div class="ys-field"><label class="ys-label">Policy ID (e.g. DOC-OP-001)</label>
            <input class="ys-input" id="doc-pid" .value=${n.policy_id} @input=${(e) => this._set('policy_id', e.target.value)}></div>
          <div class="ys-field"><label class="ys-label">Code (e.g. DOCUMENT_BLOCKED)</label>
            <input class="ys-input" id="doc-code" placeholder="DOCUMENT_BLOCKED — A–Z, 0–9, underscore only"
              .value=${n.code} @input=${(e) => this._set('code', e.target.value)}></div>
          <div class="ys-field"><label class="ys-label">Name</label>
            <input class="ys-input" .value=${n.name} @input=${(e) => this._set('name', e.target.value)}></div>
          <div class="ys-field"><label class="ys-label">Description</label>
            <input class="ys-input" .value=${n.description} @input=${(e) => this._set('description', e.target.value)}></div>
          <div class="ys-field"><label class="ys-label">User message (layman alert)</label>
            <input class="ys-input" id="doc-msg" .value=${n.user_message} @input=${(e) => this._set('user_message', e.target.value)}></div>
          <label class="ys-svc-card">
            <input type="checkbox" ?checked=${n.small_set_escalation} @change=${(e) => this._set('small_set_escalation', e.target.checked)}>
            <span class="ys-svc-name">Small-set (k-anonymity) escalation</span></label>
          <button class="ys-btn" id="doc-create" @click=${() => this._create()}>Add policy</button>
        </div>
      </div>`;
  }

  _renderInspect() {
    const r = this._inspectResult;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Inspect a sample (real OPA path)</div>
        <div class="ys-panel-body">
          <div class="ys-field"><textarea class="ys-textarea" id="doc-sample" .value=${this._sample}
            @input=${(e) => { this._sample = e.target.value; }}
            placeholder="Paste sample document text…"></textarea></div>
          <button class="ys-btn" id="doc-inspect" @click=${() => this._inspect()}>Inspect</button>
          ${r ? html`<pre class="ys-md" id="doc-inspect-result">${JSON.stringify(r, null, 2)}</pre>` : nothing}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderStatus()}
        <div class="ys-admin-2col">
          ${this._renderPolicies()}
          ${this._renderCreate()}
        </div>
        ${this._renderInspect()}
      </div>`;
  }
}

customElements.define('ys-admin-documents', YsAdminDocuments);

registerAdminModule({
  id: 'documents',
  label: 'Document protection',
  icon: '🗎',
  order: 20,
  group: 'governance',
  render: (ctx) => html`<ys-admin-documents .api=${ctx.api} .app=${ctx.app}></ys-admin-documents>`,
});
