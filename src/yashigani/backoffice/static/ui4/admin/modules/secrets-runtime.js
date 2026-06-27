// Yashigani 4.0 admin shell — Secrets & Runtime module ("Ops & Crypto" group).
//
// Two surfaces:
//   Secret rotation (parity GAP SE-01, the highest-impact one-click op):
//     POST /api/v1/admin/secrets/rotate  → rotate a named secret (STEP-UP)
//   Runtime settings (rebuild of static/js/runtime-settings.js, RS-01/03/04):
//     GET  /admin/runtime-settings          → typed setting list
//     PUT  /admin/runtime-settings/{key}    → set value (STEP-UP)
//     POST /admin/runtime-settings/{key}/reset → reset to install default (STEP-UP)
//
// TRUSTED-CHROME: secret NAMES (never values), setting keys/values/sources are
// server-authored and rendered via Lit auto-escape — no §3 markdown sink. Every
// mutation here is StepUpAdminSession server-side, so routing through ctx.api.mutate
// makes the shell's TOTP step-up fire transparently (RISK-103). Secret rotation
// carries an explicit impact banner + typed confirmation before it can run.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const ROTATABLE = [
  { value: 'postgres_password', label: 'PostgreSQL password' },
  { value: 'redis_password', label: 'Redis password' },
  { value: 'jwt_signing_key', label: 'JWT signing key' },
  { value: 'hmac_key', label: 'HMAC key' },
  { value: 'all', label: 'All secrets (full rotation)' },
];

function coerce(raw, type) {
  if (type === 'int') { const n = parseInt(raw, 10); return Number.isNaN(n) ? null : n; }
  if (type === 'float') { const n = parseFloat(raw); return Number.isNaN(n) ? null : n; }
  if (type === 'bool') {
    const lc = raw.toLowerCase();
    if (lc === 'true' || lc === '1') return true;
    if (lc === 'false' || lc === '0') return false;
    return null;
  }
  return raw; // string/json — server validates
}

export class YsAdminSecretsRuntime extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _settings: { state: true },
    _rotateSecret: { state: true },
    _rotateConfirm: { state: true },
    _rotateResult: { state: true },
    _busy: { state: true },
    _edit: { state: true },       // {key, value, type} | null
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._settings = [];
    this._rotateSecret = '';
    this._rotateConfirm = '';
    this._rotateResult = null;
    this._busy = false;
    this._edit = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const rs = await this.api.get('/admin/runtime-settings');
    this._settings = (rs && Array.isArray(rs.settings)) ? rs.settings : [];
    this._loading = false;
  }

  _toast(msg, kind) { if (this.app && this.app.toast) this.app.toast(msg, kind); }

  // ── Secret rotation ──────────────────────────────────────────────────────────
  async _rotate() {
    if (this._busy) return;
    if (!this._rotateSecret) { this._toast('Choose a secret to rotate.', 'error'); return; }
    if (this._rotateConfirm.trim().toUpperCase() !== 'ROTATE') {
      this._toast('Type ROTATE to confirm.', 'error'); return;
    }
    this._busy = true;
    this._rotateResult = null;
    // STEP-UP gated server-side (StepUpAdminSession) → TOTP modal fires via mutate.
    const res = await this.api.mutate('/api/v1/admin/secrets/rotate', {
      method: 'POST', body: { secret: this._rotateSecret },
    });
    this._busy = false;
    if (res.ok) {
      this._rotateResult = res.data;
      this._rotateConfirm = '';
      this._toast(res.data && res.data.success ? 'Secret rotation succeeded.' : 'Rotation finished with issues.',
        res.data && res.data.success ? 'success' : 'error');
    } else {
      this._toast((res.error && res.error.message) || 'Rotation request failed.', 'error');
    }
  }

  _renderRotateResult() {
    const r = this._rotateResult;
    if (!r) return nothing;
    const children = Array.isArray(r.child_results) ? r.child_results : [];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Rotation result — ${r.secret || ''}
          ${r.success ? html`<span class="ys-badge ys-badge-green">success</span>` : html`<span class="ys-badge ys-badge-red">failed</span>`}
        </div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">Request ${r.request_id || '—'} · rotated at ${r.rotated_at || '—'}</div>
          ${r.warning ? html`<div class="ys-field-error">${r.warning}</div>` : nothing}
          ${r.error ? html`<div class="ys-field-error">${r.error}</div>` : nothing}
          ${children.length
            ? html`<table class="ys-table">
                <thead><tr><th>Secret</th><th>Result</th><th>Reverted</th></tr></thead>
                <tbody>${children.map((c) => html`
                  <tr><td>${c.secret}</td>
                    <td>${c.success ? html`<span class="ys-badge ys-badge-green">ok</span>` : html`<span class="ys-badge ys-badge-red">${c.error || 'failed'}</span>`}</td>
                    <td>${c.reverted ? (c.revert_failed ? 'revert FAILED' : 'reverted') : '—'}</td></tr>`)}
                </tbody></table>`
            : nothing}
        </div>
      </div>`;
  }

  _renderRotation() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Secret rotation <span class="ys-badge ys-badge-red">high impact</span></div>
        <div class="ys-panel-body">
          <div class="ys-field-error">
            Rotating a secret immediately re-keys the live deployment. A failed rotation auto-reverts;
            a failed revert leaves services inconsistent and needs manual recovery. This requires step-up TOTP.
          </div>
          <div class="ys-field">
            <label class="ys-label">Secret</label>
            <select class="ys-select" .value=${this._rotateSecret}
                    @change=${(e) => { this._rotateSecret = e.target.value; }}>
              <option value="">— select secret —</option>
              ${ROTATABLE.map((s) => html`<option value=${s.value}>${s.label}</option>`)}
            </select>
          </div>
          <div class="ys-field">
            <label class="ys-label">Type ROTATE to confirm</label>
            <input class="ys-input" .value=${this._rotateConfirm}
                   @input=${(e) => { this._rotateConfirm = e.target.value; }}>
          </div>
          <button class="ys-btn ys-btn-danger" ?disabled=${this._busy} @click=${() => this._rotate()}>
            ${this._busy ? 'Rotating…' : 'Rotate secret (step-up)'}
          </button>
        </div>
      </div>
      ${this._renderRotateResult()}`;
  }

  // ── Runtime settings ──────────────────────────────────────────────────────────
  _startEdit(s) {
    this._edit = { key: s.key, value: String(s.value), type: s.value_type || 'string' };
  }

  async _saveEdit() {
    const e = this._edit;
    if (!e) return;
    const v = coerce(e.value.trim(), e.type);
    if (v === null) { this._toast(`Value must be a valid ${e.type}.`, 'error'); return; }
    // STEP-UP gated server-side.
    const res = await this.api.mutate(`/admin/runtime-settings/${encodeURIComponent(e.key)}`, {
      method: 'PUT', body: { value: v },
    });
    if (res.ok) { this._toast(`Setting "${e.key}" updated.`, 'success'); this._edit = null; await this._load(); }
    else this._toast((res.error && res.error.message) || 'Update failed.', 'error');
  }

  async _resetSetting(key) {
    if (!window.confirm(`Reset "${key}" to its install-time default? Requires step-up.`)) return;
    // STEP-UP gated server-side.
    const res = await this.api.mutate(`/admin/runtime-settings/${encodeURIComponent(key)}/reset`, { method: 'POST' });
    if (res.ok) { this._toast(`Setting "${key}" reset.`, 'success'); await this._load(); }
    else this._toast((res.error && res.error.message) || 'Reset failed.', 'error');
  }

  _sourceBadge(src) {
    if (src === 'env') return html`<span class="ys-badge ys-badge-blue">env</span>`;
    if (src === 'ui' || src === 'api') return html`<span class="ys-badge ys-badge-green">${src}</span>`;
    return html`<span class="ys-badge ys-badge-amber">${src || 'default'}</span>`;
  }

  _renderSettings() {
    const e = this._edit;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Runtime settings</div>
        <div class="ys-panel-body">
          ${this._settings.length === 0
            ? html`<div class="ys-txt-note">No runtime settings registered.</div>`
            : html`<table class="ys-table">
                <thead><tr><th>Key</th><th>Value</th><th>Source</th><th>Changed by</th><th>Actions</th></tr></thead>
                <tbody>
                  ${this._settings.map((s) => html`
                    <tr>
                      <td><code class="ys-system-chrome-code">${s.key}</code></td>
                      <td>${String(s.value)}</td>
                      <td>${this._sourceBadge(s.source)}</td>
                      <td>${s.changed_by || '—'}</td>
                      <td>
                        <button class="ys-btn ys-btn-ghost" @click=${() => this._startEdit(s)}>Edit</button>
                        <button class="ys-btn ys-btn-secondary" @click=${() => this._resetSetting(s.key)}>Reset</button>
                      </td>
                    </tr>`)}
                </tbody>
              </table>`}
          ${e ? html`
            <div class="ys-field">
              <label class="ys-label">Edit ${e.key} (${e.type})</label>
              <input class="ys-input" type=${e.type === 'int' || e.type === 'float' ? 'number' : 'text'}
                     .value=${e.value} @input=${(ev) => { this._edit = { ...e, value: ev.target.value }; }}>
            </div>
            <button class="ys-btn" @click=${() => this._saveEdit()}>Save (step-up)</button>
            <button class="ys-btn ys-btn-ghost" @click=${() => { this._edit = null; }}>Cancel</button>
          ` : nothing}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading secrets & runtime…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <h2 class="ys-admin-section-title">Secrets &amp; Runtime</h2>
        ${this._renderRotation()}
        ${this._renderSettings()}
      </div>`;
  }
}

customElements.define('ys-admin-secrets-runtime', YsAdminSecretsRuntime);

registerAdminModule({
  id: 'secrets-runtime',
  label: 'Secrets & Runtime',
  icon: '⚙',
  order: 66,
  render: (ctx) => html`
    <ys-admin-secrets-runtime .api=${ctx.api} .app=${ctx.app}></ys-admin-secrets-runtime>`,
});
