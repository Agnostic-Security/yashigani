// Yashigani 4.0 admin shell — Identity & Access: Security & Auth module group.
//
// Three nav sections registered from this file:
//   • #webauthn  — Passkeys / WebAuthn credentials (routes/webauthn_v1.py)
//   • #hibp      — Have-I-Been-Pwned API key       (routes/hibp.py)
//   • #ratelimit — Rate-limit config + overrides   (routes/ratelimit.py)
//
// STEP-UP: WebAuthn credential revoke, HIBP key set/clear all carry
// StepUpAdminSession server-side — the ApiClient's server-driven step-up
// interceptor raises the shared TOTP modal automatically. Rate-limit routes use
// a plain AdminSession (not in the RISK-103 re-tier set) and are not gated.
//
// TRUSTED-CHROME: all values are server-authored config/status shown via Lit
// auto-escape; the §3 markdown sink is never used. The WebAuthn registration
// ceremony uses the standards JSON helpers (parseCreationOptionsFromJSON /
// PublicKeyCredential.toJSON) — no manual base64 DOM injection.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';
import { reportMutate, shortTs } from './_iam.js';

void widgets;

// ── WebAuthn / passkeys ──────────────────────────────────────────────────────
export class YsAdminWebauthn extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _creds: { state: true },
    _newName: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._creds = [];
    this._newName = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const list = await this.api.get('/api/v1/admin/webauthn/credentials');
    this._creds = (list && Array.isArray(list.credentials)) ? list.credentials : [];
    this._loading = false;
  }

  async _register() {
    const name = (this._newName || '').trim() || 'admin passkey';
    const start = await this.api.mutate('/api/v1/admin/webauthn/register/start', {
      method: 'POST', body: { credential_name: name },
    });
    if (!start.ok || !start.data || !start.data.options) { reportMutate(this.app, start, ''); return; }
    if (!(window.PublicKeyCredential && typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function')) {
      this.app && this.app.toast('This browser cannot register passkeys (WebAuthn JSON API unavailable).', 'error');
      return;
    }
    try {
      let optsJson = start.data.options;
      if (typeof optsJson === 'string') optsJson = JSON.parse(optsJson);
      const opts = PublicKeyCredential.parseCreationOptionsFromJSON(optsJson);
      const cred = await navigator.credentials.create({ publicKey: opts });
      const finish = await this.api.mutate('/api/v1/admin/webauthn/register/finish', {
        method: 'POST', body: { credential_response: cred.toJSON(), credential_name: name },
      });
      if (reportMutate(this.app, finish, 'Passkey registered.')) {
        this._newName = '';
        await this._load();
      }
    } catch {
      this.app && this.app.toast('Passkey registration was cancelled or failed.', 'error');
    }
  }

  async _revoke(id) {
    // DELETE carries StepUpAdminSession — ApiClient raises the TOTP modal.
    const res = await this.api.mutate(`/api/v1/admin/webauthn/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'Passkey revoked.')) await this._load();
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading passkeys…</div></div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="webauthn">
      <div class="ys-panel">
        <div class="ys-panel-header">Register a passkey</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Credential name</label>
            <input class="ys-input" type="text" .value=${this._newName}
                   placeholder="YubiKey 5C" @input=${(e) => { this._newName = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._register()}>Register passkey</button>
          <div class="ys-txt-note">Password + TOTP login remains available; passkeys cannot all be removed while WebAuthn is the only factor.</div>
        </div>
      </div>
      <div class="ys-panel">
        <div class="ys-panel-header">Registered passkeys (${this._creds.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>Name</th><th>AAGUID</th><th>Sign count</th><th>Created</th><th>Last used</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._creds.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No passkeys registered.</td></tr>`
                : this._creds.map((c) => html`<tr>
                    <td>${c.name || ''}</td>
                    <td>${c.aaguid || ''}</td>
                    <td>${c.sign_count == null ? '' : c.sign_count}</td>
                    <td>${shortTs(c.created_at)}</td>
                    <td>${c.last_used_at ? shortTs(c.last_used_at) : '—'}</td>
                    <td><button class="ys-btn ys-btn-danger" @click=${() => this._revoke(c.id)}>Revoke (step-up)</button></td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-webauthn', YsAdminWebauthn);

// ── HIBP API key ─────────────────────────────────────────────────────────────
export class YsAdminHibp extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _status: { state: true },
    _newKey: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._status = null;
    this._newKey = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    this._status = await this.api.get('/api/v1/admin/auth/hibp/status');
    this._loading = false;
  }

  async _save() {
    const api_key = (this._newKey || '').trim();
    if (!api_key) { this.app && this.app.toast('Enter an HIBP API key.', 'error'); return; }
    // PUT carries StepUpAdminSession — ApiClient raises the TOTP modal.
    const res = await this.api.mutate('/api/v1/admin/auth/hibp/key', { method: 'PUT', body: { api_key } });
    if (reportMutate(this.app, res, 'HIBP key saved.')) {
      this._newKey = '';
      await this._load();
    }
  }

  async _clear() {
    const res = await this.api.mutate('/api/v1/admin/auth/hibp/key', { method: 'DELETE' });
    if (reportMutate(this.app, res, 'HIBP key cleared.')) await this._load();
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading HIBP config…</div></div>`;
    }
    const s = this._status || {};
    return html`<div class="ys-admin-content-pad" data-module="hibp">
      <div class="ys-panel">
        <div class="ys-panel-header">Have I Been Pwned — breach check key</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Status: ${s.configured ? 'configured' : 'not configured'} ·
            source: ${s.source || 'none'}${s.masked_value ? ` · key: ${s.masked_value}` : ''}${s.updated_by ? ` · by ${s.updated_by}` : ''}
          </div>
          <div class="ys-field">
            <label class="ys-label">API key</label>
            <input class="ys-input" type="password" autocomplete="off" .value=${this._newKey}
                   @input=${(e) => { this._newKey = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._save()}>Save key (step-up)</button>
          ${s.source === 'admin_panel'
            ? html`<button class="ys-btn ys-btn-danger" @click=${() => this._clear()}>Clear key (step-up)</button>`
            : nothing}
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-hibp', YsAdminHibp);

// ── Rate limiting ────────────────────────────────────────────────────────────
const RL_NUM_FIELDS = [
  ['global_rps', 'Global RPS'], ['global_burst', 'Global burst'],
  ['per_ip_rps', 'Per-IP RPS'], ['per_ip_burst', 'Per-IP burst'],
  ['per_agent_rps', 'Per-agent RPS'], ['per_agent_burst', 'Per-agent burst'],
  ['per_session_rps', 'Per-session RPS'], ['per_session_burst', 'Per-session burst'],
  ['rpi_scale_medium', 'RPI scale medium'], ['rpi_scale_high', 'RPI scale high'],
  ['rpi_scale_critical', 'RPI scale critical'],
];

export class YsAdminRatelimit extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _cfg: { state: true },
    _status: { state: true },
    _endpoints: { state: true },
    _newEp: { state: true },        // {endpoint_template, rps, burst, window_seconds}
    _resetKey: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._cfg = null;
    this._status = null;
    this._endpoints = [];
    this._newEp = { endpoint_template: '', rps: '', burst: '', window_seconds: '1' };
    this._resetKey = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [cfg, status, eps] = await Promise.all([
      this.api.get('/admin/ratelimit/config'),
      this.api.get('/admin/ratelimit/status'),
      this.api.get('/admin/ratelimit/endpoints'),
    ]);
    this._cfg = (cfg && cfg.configured) ? cfg : (cfg || null);
    this._status = status || null;
    this._endpoints = (eps && Array.isArray(eps.endpoints)) ? eps.endpoints : [];
    this._loading = false;
  }

  _set(name, value) { this._cfg = { ...(this._cfg || {}), [name]: value }; }

  async _save() {
    const c = this._cfg || {};
    const body = {
      enabled: !!c.enabled,
      adaptive_enabled: !!c.adaptive_enabled,
    };
    for (const [k] of RL_NUM_FIELDS) {
      const n = Number(c[k]);
      if (Number.isFinite(n)) body[k] = n;
    }
    const res = await this.api.mutate('/admin/ratelimit/config', { method: 'PUT', body });
    if (reportMutate(this.app, res, 'Rate-limit config saved.')) await this._load();
  }

  async _addEndpoint() {
    const e = this._newEp;
    const tmpl = (e.endpoint_template || '').trim();
    const rps = Number(e.rps); const burst = Number(e.burst);
    const window_seconds = Number(e.window_seconds) || 1;
    if (!tmpl || !Number.isFinite(rps) || !Number.isFinite(burst)) {
      this.app && this.app.toast('Template, RPS and burst are required.', 'error');
      return;
    }
    const res = await this.api.mutate('/admin/ratelimit/endpoints', {
      method: 'POST', body: { endpoint_template: tmpl, rps, burst, window_seconds },
    });
    if (reportMutate(this.app, res, 'Endpoint override set.')) {
      this._newEp = { endpoint_template: '', rps: '', burst: '', window_seconds: '1' };
      await this._load();
    }
  }

  async _deleteEndpoint(hash) {
    const res = await this.api.mutate(`/admin/ratelimit/endpoints/${encodeURIComponent(hash)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'Endpoint override deleted.')) await this._load();
  }

  async _resetBucket() {
    const key = (this._resetKey || '').trim();
    if (!key) { this.app && this.app.toast('Enter a bucket key.', 'error'); return; }
    const res = await this.api.mutate(`/admin/ratelimit/reset/${encodeURIComponent(key)}`, { method: 'POST' });
    if (reportMutate(this.app, res, 'Bucket reset.')) this._resetKey = '';
  }

  _renderStatus() {
    const s = this._status;
    if (!s || !s.configured) return nothing;
    return html`<div class="ys-panel">
      <div class="ys-panel-header">Live status</div>
      <div class="ys-panel-body ys-txt-note">
        enabled=${s.enabled ? 'yes' : 'no'} · adaptive=${s.adaptive_enabled ? 'yes' : 'no'} ·
        RPI=${s.current_rpi} · multiplier=${s.current_multiplier} ·
        eff. global RPS=${s.effective_global_rps}
      </div>
    </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading rate-limit config…</div></div>`;
    }
    const c = this._cfg || {};
    if (c.configured === false) {
      return html`<div class="ys-admin-content-pad" data-module="ratelimit">
        <div class="ys-panel"><div class="ys-panel-body ys-txt-note">Rate limiter is not configured in this deployment.</div></div>
      </div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="ratelimit">
      ${this._renderStatus()}
      <div class="ys-panel">
        <div class="ys-panel-header">Rate-limit configuration</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Enabled</label>
            <select class="ys-select" .value=${c.enabled ? 'true' : 'false'}
                    @change=${(e) => this._set('enabled', e.target.value === 'true')}>
              <option value="true">enabled</option><option value="false">disabled</option>
            </select>
          </div>
          <div class="ys-field">
            <label class="ys-label">Adaptive (RPI scaling)</label>
            <select class="ys-select" .value=${c.adaptive_enabled ? 'true' : 'false'}
                    @change=${(e) => this._set('adaptive_enabled', e.target.value === 'true')}>
              <option value="true">enabled</option><option value="false">disabled</option>
            </select>
          </div>
          ${RL_NUM_FIELDS.map(([key, label]) => html`
            <div class="ys-field">
              <label class="ys-label">${label}</label>
              <input class="ys-input" type="number" step="any" .value=${c[key] == null ? '' : String(c[key])}
                     @input=${(e) => this._set(key, e.target.value)}>
            </div>`)}
          <button class="ys-btn" @click=${() => this._save()}>Save config</button>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">Per-endpoint overrides</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Endpoint template</label>
            <input class="ys-input" type="text" placeholder="/agents/{agent_id}" .value=${this._newEp.endpoint_template}
                   @input=${(e) => { this._newEp = { ...this._newEp, endpoint_template: e.target.value }; }}>
          </div>
          <div class="ys-field">
            <label class="ys-label">RPS</label>
            <input class="ys-input" type="number" .value=${this._newEp.rps}
                   @input=${(e) => { this._newEp = { ...this._newEp, rps: e.target.value }; }}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Burst</label>
            <input class="ys-input" type="number" .value=${this._newEp.burst}
                   @input=${(e) => { this._newEp = { ...this._newEp, burst: e.target.value }; }}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Window seconds</label>
            <input class="ys-input" type="number" .value=${this._newEp.window_seconds}
                   @input=${(e) => { this._newEp = { ...this._newEp, window_seconds: e.target.value }; }}>
          </div>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._addEndpoint()}>Add / update override</button>
          <table class="ys-table">
            <thead><tr><th>Hash</th><th>Label</th><th>RPS</th><th>Burst</th><th>Window</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._endpoints.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No per-endpoint overrides.</td></tr>`
                : this._endpoints.map((ep) => html`<tr>
                    <td>${ep.endpoint_hash}</td><td>${ep.label || ''}</td><td>${ep.rps}</td>
                    <td>${ep.burst}</td><td>${ep.window_seconds}</td>
                    <td><button class="ys-btn ys-btn-danger" @click=${() => this._deleteEndpoint(ep.endpoint_hash)}>Delete</button></td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">Reset a bucket</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Bucket key</label>
            <input class="ys-input" type="text" .value=${this._resetKey}
                   @input=${(e) => { this._resetKey = e.target.value; }}>
          </div>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._resetBucket()}>Reset bucket</button>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-ratelimit', YsAdminRatelimit);

registerAdminModule({
  id: 'webauthn',
  label: 'Passkeys',
  icon: '🔑',
  order: 35,
  render: (ctx) => html`<ys-admin-webauthn .api=${ctx.api} .app=${ctx.app}></ys-admin-webauthn>`,
});

registerAdminModule({
  id: 'hibp',
  label: 'Breach check',
  icon: '🛡️',
  order: 36,
  render: (ctx) => html`<ys-admin-hibp .api=${ctx.api} .app=${ctx.app}></ys-admin-hibp>`,
});

registerAdminModule({
  id: 'ratelimit',
  label: 'Rate limiting',
  icon: '🚦',
  order: 37,
  render: (ctx) => html`<ys-admin-ratelimit .api=${ctx.api} .app=${ctx.app}></ys-admin-ratelimit>`,
});
