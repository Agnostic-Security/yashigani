// Yashigani 4.0 admin shell — Identity & Access: SSO & Federation module.
//
// One nav section (#sso) covering external identity federation:
//   • Configured IdPs  — read-only (routes/sso.py GET /auth/sso/select). IdP
//       config is provisioned from deployment env at boot (entrypoint.py); there
//       is no IdP-config write API, so this view is intentionally read-only.
//   • JWT validation config — full CRUD (routes/jwt_config.py): the external
//       JWKS/issuer/audience used to validate federated bearer tokens.
//   • JWT token test — POST a token and see the inspector verdict.
//
// STEP-UP: PUT/DELETE on /admin/jwt/config carry require_stepup_admin_session
// server-side, so the ApiClient's server-driven step-up interceptor raises the
// shared TOTP modal automatically (no client gate needed here).
//
// TRUSTED-CHROME: all values are server-authored config / inspector output shown
// via Lit auto-escape; the §3 markdown sink is never used.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';
import { reportMutate, yn } from './_iam.js';

void widgets;

export class YsAdminSso extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _idps: { state: true },
    _configs: { state: true },
    _platformTenant: { state: true },
    _form: { state: true },         // JWTConfigRequest draft
    _testToken: { state: true },
    _testResult: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._idps = [];
    this._configs = [];
    this._platformTenant = '';
    this._form = { tenant_id: '', jwks_url: '', issuer: '', audience: '', scope: 'platform', fail_closed: true };
    this._testToken = '';
    this._testResult = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [idps, jwt] = await Promise.all([
      this.api.get('/auth/sso/select'),
      this.api.get('/admin/jwt/config'),
    ]);
    this._idps = (idps && Array.isArray(idps.idps)) ? idps.idps : [];
    this._configs = (jwt && Array.isArray(jwt.configs)) ? jwt.configs : [];
    this._platformTenant = (jwt && jwt.platform_tenant_id) || '';
    if (!this._form.tenant_id && this._platformTenant) {
      this._form = { ...this._form, tenant_id: this._platformTenant };
    }
    this._loading = false;
  }

  _set(name, value) { this._form = { ...this._form, [name]: value }; }

  async _saveJwt() {
    const f = this._form;
    if (!f.jwks_url || !f.issuer || !f.audience) {
      this.app && this.app.toast('jwks_url, issuer and audience are required.', 'error');
      return;
    }
    const body = {
      tenant_id: f.tenant_id || this._platformTenant,
      jwks_url: f.jwks_url,
      issuer: f.issuer,
      audience: f.audience,
      scope: f.scope || 'platform',
      fail_closed: !!f.fail_closed,
    };
    // PUT carries require_stepup_admin_session — ApiClient raises step-up.
    const res = await this.api.mutate('/admin/jwt/config', { method: 'PUT', body });
    if (reportMutate(this.app, res, 'JWT config saved.')) await this._load();
  }

  async _deleteJwt(tenantId) {
    const res = await this.api.mutate(`/admin/jwt/config/${encodeURIComponent(tenantId)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'JWT config deleted.')) await this._load();
  }

  async _test() {
    const token = (this._testToken || '').trim();
    if (!token) { this.app && this.app.toast('Paste a token to test.', 'error'); return; }
    const res = await this.api.mutate('/admin/jwt/config/test', {
      method: 'POST',
      body: { token, tenant_id: this._form.tenant_id || this._platformTenant },
    });
    if (res && res.ok) {
      this._testResult = res.data;
    } else {
      this._testResult = null;
      reportMutate(this.app, res, '');
    }
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading SSO & federation…</div></div>`;
    }
    const f = this._form;
    const tr = this._testResult;
    return html`<div class="ys-admin-content-pad" data-module="sso">
      <div class="ys-panel">
        <div class="ys-panel-header">Configured identity providers (${this._idps.length})</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">IdPs are provisioned from deployment configuration at boot — read-only here.</div>
          <table class="ys-table">
            <thead><tr><th>ID</th><th>Name</th><th>Protocol</th><th>Email domains</th></tr></thead>
            <tbody>
              ${this._idps.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="4">No IdPs configured.</td></tr>`
                : this._idps.map((i) => html`<tr>
                    <td>${i.id}</td><td>${i.name}</td><td>${i.protocol}</td>
                    <td>${Array.isArray(i.email_domains) ? i.email_domains.join(', ') : ''}</td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">JWT validation config</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Tenant ID</label>
            <input class="ys-input" type="text" .value=${f.tenant_id}
                   @input=${(e) => this._set('tenant_id', e.target.value)}>
          </div>
          <div class="ys-field">
            <label class="ys-label">JWKS URL</label>
            <input class="ys-input" type="text" .value=${f.jwks_url}
                   placeholder="https://idp.example.com/.well-known/jwks.json"
                   @input=${(e) => this._set('jwks_url', e.target.value)}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Issuer</label>
            <input class="ys-input" type="text" .value=${f.issuer}
                   @input=${(e) => this._set('issuer', e.target.value)}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Audience</label>
            <input class="ys-input" type="text" .value=${f.audience}
                   @input=${(e) => this._set('audience', e.target.value)}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Scope</label>
            <select class="ys-select" .value=${f.scope}
                    @change=${(e) => this._set('scope', e.target.value)}>
              <option value="platform">platform</option>
              <option value="tenant">tenant</option>
            </select>
          </div>
          <div class="ys-field">
            <label class="ys-label">Fail closed</label>
            <select class="ys-select" .value=${f.fail_closed ? 'true' : 'false'}
                    @change=${(e) => this._set('fail_closed', e.target.value === 'true')}>
              <option value="true">true (reject on validation failure)</option>
              <option value="false">false</option>
            </select>
          </div>
          <button class="ys-btn" @click=${() => this._saveJwt()}>Save JWT config (step-up)</button>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">JWT configs (${this._configs.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>Tenant</th><th>Issuer</th><th>Audience</th><th>Scope</th><th>Fail closed</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._configs.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No JWT configs.</td></tr>`
                : this._configs.map((c) => html`<tr>
                    <td>${c.tenant_id}</td><td>${c.issuer}</td><td>${c.audience}</td>
                    <td>${c.scope}</td><td>${yn(c.fail_closed)}</td>
                    <td><button class="ys-btn ys-btn-danger" @click=${() => this._deleteJwt(c.tenant_id)}>Delete (step-up)</button></td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">Test a JWT</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Token</label>
            <textarea class="ys-textarea" .value=${this._testToken}
                      @input=${(e) => { this._testToken = e.target.value; }}></textarea>
          </div>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._test()}>Test token</button>
          ${tr
            ? html`<div class="ys-txt-note">
                valid=${yn(tr.valid)} · sub=${tr.sub || '—'} · tenant=${tr.tenant_id || '—'}${tr.error ? ` · error=${tr.error}` : ''}
              </div>`
            : nothing}
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-sso', YsAdminSso);

registerAdminModule({
  id: 'sso',
  label: 'SSO & federation',
  icon: '🌐',
  order: 40,
  group: 'identity',
  render: (ctx) => html`<ys-admin-sso .api=${ctx.api} .app=${ctx.app}></ys-admin-sso>`,
});
