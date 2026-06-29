// Yashigani 4.0 admin shell — License & entitlements module (Governance group).
//
//   GET    /admin/license               → tier, validity, expiry, usage limits
//   GET    /admin/license/entitlements  → tier-gated feature matrix (R23)
//   POST   /admin/license/activate      → activate a key   [STEP-UP] (GAP LI-04)
//   DELETE /admin/license               → revert to community [STEP-UP] (GAP LI-05)
//
// STEP-UP (RISK-103): activate + revert are require_stepup_admin_session; the
// TOTP modal fires via ctx.api.mutate on the server's step_up_required tag.
//
// FINDING (flagged): POST /admin/license/activate currently binds its body via
// FastAPI Form(...)/File(...) (multipart), NOT the JSON ActivateRequest model
// that the module already defines. The audited ApiClient posts JSON, so this UI
// sends {license_content} JSON — which works only once the route switches to the
// ActivateRequest body. Recommend wiring the existing ActivateRequest model so
// activate is reachable via the audited client + its step-up interceptor.
//
// SAFE-RENDER: all fields are server-authored status strings rendered via Lit
// auto-escape (textContent) — no untrusted markdown sink.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminLicense extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _license: { state: true },
    _entitlements: { state: true },
    _key: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._license = null;
    this._entitlements = [];
    this._key = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const [lic, ent] = await Promise.all([
      this.api.get('/admin/license'),
      this.api.get('/admin/license/entitlements'),
    ]);
    this._license = lic || null;
    this._entitlements = (ent && Array.isArray(ent.entitlements)) ? ent.entitlements : [];
    this._loading = false;
  }

  async _activate() {
    if (!this._key.trim()) { this.app && this.app.toast('Paste a license key.', 'error'); return; }
    const res = await this.api.mutate('/admin/license/activate', { method: 'POST', body: { license_content: this._key.trim() } });
    if (res.ok) { this.app && this.app.toast('License activated.', 'success'); this._key = ''; this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Activation failed.', 'error'); }
  }

  async _revert() {
    const res = await this.api.mutate('/admin/license', { method: 'DELETE', body: { confirm: true } });
    if (res.ok) { this.app && this.app.toast('Reverted to community.', 'success'); this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Revert failed.', 'error'); }
  }

  _limitRow(label, block) {
    if (!block) return nothing;
    const max = block.unlimited ? '∞' : (block.maximum ?? '—');
    const over = !block.unlimited && block.maximum != null && block.current > block.maximum;
    return html`
      <li class="ys-alert-item">
        <span class="ys-alert-label">${label}</span>
        <span class="ys-alert-count ${over ? 'ys-stat-num--warn' : ''}">${block.current} / ${max}</span>
      </li>`;
  }

  _renderStatus() {
    const l = this._license;
    if (!l) return html`<div class="ys-panel"><div class="ys-panel-header">License</div>
      <div class="ys-panel-body"><div class="ys-txt-note">License status unavailable.</div></div></div>`;
    const lim = l.limits || {};
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          <span class="ys-semaphore ${l.valid ? 'ys-semaphore--ok' : 'ys-semaphore--critical'}"></span>
          License — ${l.tier}${l.valid ? '' : ' (invalid)'}
        </div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">org: ${l.org_domain || '*'} · id: ${l.license_id || '—'} · expires: ${l.expires_at || 'never'}</div>
          <ul class="ys-alert-list">
            ${this._limitRow('Agents', lim.agents)}
            ${this._limitRow('End users', lim.end_users)}
            ${this._limitRow('Admin seats', lim.admin_seats)}
            ${this._limitRow('Orgs', lim.orgs)}
          </ul>
        </div>
      </div>`;
  }

  _renderEntitlements() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Entitlements</div>
        <div class="ys-panel-body">
          ${this._entitlements.length === 0
            ? html`<div class="ys-txt-note">No entitlement data.</div>`
            : this._entitlements.map((e) => html`
                <div class="ys-svc-card">
                  <span class="ys-badge ${e.available ? 'ys-badge-green' : 'ys-badge-red'}">${e.available ? 'included' : 'locked'}</span>
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${e.label}</div>
                    <div class="ys-txt-note">${e.available ? '' : `requires ${e.required_tier_label}`}</div>
                  </div>
                </div>`)}
        </div>
      </div>`;
  }

  _renderManage() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Activate / revert (step-up)</div>
        <div class="ys-panel-body">
          <div class="ys-field"><label class="ys-label">License key</label>
            <textarea class="ys-textarea" id="lic-key" .value=${this._key}
              @input=${(e) => { this._key = e.target.value; }}
              placeholder="Paste signed license content…"></textarea></div>
          <button class="ys-btn" id="lic-activate" @click=${() => this._activate()}>Activate</button>
          <button class="ys-btn ys-btn-danger" id="lic-revert" @click=${() => this._revert()}>Revert to community</button>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading license…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-admin-2col">
          ${this._renderStatus()}
          ${this._renderEntitlements()}
        </div>
        ${this._renderManage()}
      </div>`;
  }
}

customElements.define('ys-admin-license', YsAdminLicense);

registerAdminModule({
  id: 'license',
  label: 'License',
  icon: '⬡',
  order: 40,
  group: 'platform',
  render: (ctx) => html`<ys-admin-license .api=${ctx.api} .app=${ctx.app}></ys-admin-license>`,
});
