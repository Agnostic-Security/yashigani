// Yashigani 4.0 admin shell — Identity & Access: Accounts module group.
//
// Two nav sections registered from this file:
//   • #accounts — Admin accounts (routes/accounts.py, prefix /admin/accounts)
//   • #users    — User accounts  (routes/users.py,    prefix /admin/users)
//
// Replicates the 3.0 dashboard.js admin/user-management pages on the hardened
// shared layer, and CLOSES the parity gaps (admin force-reset, user full-reset,
// reactivate, admin-issued API key, sensitivity ceiling) that had no WebUI.
//
// TRUSTED-CHROME: every value here is a server-authored account field shown via
// Lit auto-escape (textContent). No model/agent/document output reaches this
// surface; the §3 markdown sink is never used. All writes go through the shared
// ApiClient.mutate() — step-up tagged routes (delete/disable/update/force-reset/
// full-reset/reactivate/api-key) transparently raise the shared TOTP modal via
// the client's server-driven interceptor (RISK-103). Reads tolerate null.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';
import { reportMutate, yn, shortTs } from './_iam.js';

void widgets;

const SENSITIVITY_LEVELS = ['public', 'internal', 'confidential', 'restricted'];

// ── Admin accounts ───────────────────────────────────────────────────────────
export class YsAdminAccounts extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _rows: { state: true },
    _enforcement: { state: true },
    _newUser: { state: true },
    _edit: { state: true },        // {username, email, disabled}
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._rows = [];
    this._enforcement = null;
    this._newUser = '';
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
    const [list, enforcement] = await Promise.all([
      this.api.get('/admin/accounts'),
      this.api.get('/admin/accounts/enforcement'),
    ]);
    this._rows = (list && Array.isArray(list.accounts)) ? list.accounts : [];
    this._enforcement = (enforcement && typeof enforcement === 'object') ? enforcement : null;
    this._loading = false;
  }

  async _create() {
    const username = (this._newUser || '').trim();
    if (!username) { this.app && this.app.toast('Username is required.', 'error'); return; }
    const res = await this.api.mutate('/admin/accounts', { method: 'POST', body: { username } });
    if (reportMutate(this.app, res, 'Admin account created.')) {
      this._newUser = '';
      await this._load();
    }
  }

  // All of the following hit StepUpAdminSession routes — the ApiClient's
  // server-driven step-up interceptor raises the TOTP modal automatically.
  async _setDisabled(username, disabled) {
    const path = `/admin/accounts/${encodeURIComponent(username)}/${disabled ? 'disable' : 'enable'}`;
    const res = await this.api.mutate(path, { method: 'POST' });
    if (reportMutate(this.app, res, disabled ? 'Account disabled.' : 'Account enabled.')) await this._load();
  }

  async _forceReset(username, action) {
    const res = await this.api.mutate(
      `/admin/accounts/${encodeURIComponent(username)}/force-reset`,
      { method: 'POST', body: { action } },
    );
    reportMutate(this.app, res, action === 'password_reset' ? 'Password reset forced.' : 'TOTP reprovision forced.');
    await this._load();
  }

  async _delete(username) {
    const res = await this.api.mutate(`/admin/accounts/${encodeURIComponent(username)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'Admin account deleted.')) await this._load();
  }

  async _saveEdit() {
    const e = this._edit;
    if (!e) return;
    const body = {};
    if (e.email != null) body.email = e.email;
    if (e.disabled != null) body.disabled = !!e.disabled;
    const res = await this.api.mutate(`/admin/accounts/${encodeURIComponent(e.username)}`, { method: 'PUT', body });
    if (reportMutate(this.app, res, 'Admin account updated.')) {
      this._edit = null;
      await this._load();
    }
  }

  _renderEnforcement() {
    const e = this._enforcement;
    if (!e) return nothing;
    if (!e.action_required && !e.below_soft_target) return nothing;
    const cls = e.action_required ? 'ys-badge ys-badge-red' : 'ys-badge ys-badge-amber';
    const msg = e.action_required
      ? `Below minimum: ${e.active}/${e.total} active — add a second admin (min total ${e.min_total}, min active ${e.min_active}).`
      : `Below recommended target (${e.soft_target}) for separation of duties.`;
    return html`<div class="ys-panel"><div class="ys-panel-body">
      <span class=${cls}>enforcement</span> <span class="ys-txt-note">${msg}</span>
    </div></div>`;
  }

  _renderEdit() {
    const e = this._edit;
    if (!e) return nothing;
    return html`<div class="ys-panel">
      <div class="ys-panel-header">Edit admin — ${e.username}</div>
      <div class="ys-panel-body">
        <div class="ys-field">
          <label class="ys-label">Email</label>
          <input class="ys-input" type="email" .value=${e.email || ''}
                 @input=${(ev) => { this._edit = { ...this._edit, email: ev.target.value }; }}>
        </div>
        <div class="ys-field">
          <label class="ys-label">Disabled</label>
          <select class="ys-select" .value=${e.disabled ? 'true' : 'false'}
                  @change=${(ev) => { this._edit = { ...this._edit, disabled: ev.target.value === 'true' }; }}>
            <option value="false">active</option>
            <option value="true">disabled</option>
          </select>
        </div>
        <button class="ys-btn" @click=${() => this._saveEdit()}>Save (step-up)</button>
        <button class="ys-btn ys-btn-secondary" @click=${() => { this._edit = null; }}>Cancel</button>
      </div>
    </div>`;
  }

  _renderRow(r) {
    return html`<tr>
      <td>${r.username}</td>
      <td>${r.email || ''}</td>
      <td>${r.disabled ? 'disabled' : 'active'}</td>
      <td>${yn(r.force_password_change)}</td>
      <td>${yn(r.force_totp_provision)}</td>
      <td>${shortTs(r.created_at)}</td>
      <td>
        <button class="ys-btn ys-btn-ghost" @click=${() => { this._edit = { username: r.username, email: r.email || '', disabled: !!r.disabled }; }}>Edit</button>
        ${r.disabled
          ? html`<button class="ys-btn ys-btn-ghost" @click=${() => this._setDisabled(r.username, false)}>Enable</button>`
          : html`<button class="ys-btn ys-btn-ghost" @click=${() => this._setDisabled(r.username, true)}>Disable</button>`}
        <button class="ys-btn ys-btn-ghost" @click=${() => this._forceReset(r.username, 'password_reset')}>Reset pwd</button>
        <button class="ys-btn ys-btn-ghost" @click=${() => this._forceReset(r.username, 'totp_reprovision')}>Reprov TOTP</button>
        <button class="ys-btn ys-btn-danger" @click=${() => this._delete(r.username)}>Delete</button>
      </td>
    </tr>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading admin accounts…</div></div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="accounts">
      ${this._renderEnforcement()}
      <div class="ys-panel">
        <div class="ys-panel-header">Create admin account</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Username</label>
            <input class="ys-input" type="text" .value=${this._newUser}
                   placeholder="new-admin"
                   @input=${(e) => { this._newUser = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._create()}>Create</button>
        </div>
      </div>
      ${this._renderEdit()}
      <div class="ys-panel">
        <div class="ys-panel-header">Admin accounts (${this._rows.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr>
              <th>Username</th><th>Email</th><th>Status</th><th>Force pwd</th>
              <th>Force TOTP</th><th>Created</th><th>Actions</th>
            </tr></thead>
            <tbody>
              ${this._rows.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="7">No admin accounts.</td></tr>`
                : this._rows.map((r) => this._renderRow(r))}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-accounts', YsAdminAccounts);

// ── User accounts ────────────────────────────────────────────────────────────
export class YsAdminUsers extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _rows: { state: true },
    _new: { state: true },          // {email, username}
    _edit: { state: true },         // {username, email, disabled, sensitivity_ceiling}
    _reset: { state: true },        // {username, totp_code}
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._rows = [];
    this._new = { email: '', username: '' };
    this._edit = null;
    this._reset = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const list = await this.api.get('/admin/users');
    this._rows = (list && Array.isArray(list.users)) ? list.users : [];
    this._loading = false;
  }

  async _create() {
    const email = (this._new.email || '').trim();
    if (!email) { this.app && this.app.toast('Email is required.', 'error'); return; }
    const body = { email };
    const u = (this._new.username || '').trim();
    if (u) body.username = u;
    const res = await this.api.mutate('/admin/users', { method: 'POST', body });
    if (reportMutate(this.app, res, 'User created.')) {
      this._new = { email: '', username: '' };
      await this._load();
    }
  }

  async _setDisabled(username, disabled) {
    const path = `/admin/users/${encodeURIComponent(username)}/${disabled ? 'disable' : 'enable'}`;
    const res = await this.api.mutate(path, { method: 'POST' });
    if (reportMutate(this.app, res, disabled ? 'User disabled.' : 'User enabled.')) await this._load();
  }

  async _reactivate(username) {
    const res = await this.api.mutate(
      `/admin/users/${encodeURIComponent(username)}/reactivate`,
      { method: 'POST', body: { reason: 'admin reactivation' } },
    );
    if (reportMutate(this.app, res, 'User reactivated.')) await this._load();
  }

  async _issueApiKey(username) {
    const res = await this.api.mutate(`/admin/users/${encodeURIComponent(username)}/api-key`, { method: 'POST' });
    if (res && res.ok && res.data && res.data.plaintext_token) {
      this.app && this.app.toast(`API key (shown once): ${res.data.plaintext_token}`, 'success');
    } else {
      reportMutate(this.app, res, 'API key issued.');
    }
  }

  async _delete(username) {
    const res = await this.api.mutate(`/admin/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'User deleted.')) await this._load();
  }

  async _saveEdit() {
    const e = this._edit;
    if (!e) return;
    const body = {};
    if (e.email != null && e.email !== '') body.email = e.email;
    if (e.disabled != null) body.disabled = !!e.disabled;
    if (e.sensitivity_ceiling) body.sensitivity_ceiling = e.sensitivity_ceiling;
    const res = await this.api.mutate(`/admin/users/${encodeURIComponent(e.username)}`, { method: 'PUT', body });
    if (reportMutate(this.app, res, 'User updated.')) {
      this._edit = null;
      await this._load();
    }
  }

  async _fullReset() {
    const r = this._reset;
    if (!r) return;
    const code = (r.totp_code || '').trim();
    if (!/^\d{6}$/.test(code)) { this.app && this.app.toast('A 6-digit admin TOTP code is required.', 'error'); return; }
    const res = await this.api.mutate(
      `/admin/users/${encodeURIComponent(r.username)}/full-reset`,
      { method: 'POST', body: { totp_code: code } },
    );
    if (reportMutate(this.app, res, 'User fully reset.')) {
      this._reset = null;
      await this._load();
    }
  }

  _renderEdit() {
    const e = this._edit;
    if (!e) return nothing;
    return html`<div class="ys-panel">
      <div class="ys-panel-header">Edit user — ${e.username}</div>
      <div class="ys-panel-body">
        <div class="ys-field">
          <label class="ys-label">Email</label>
          <input class="ys-input" type="email" .value=${e.email || ''}
                 @input=${(ev) => { this._edit = { ...this._edit, email: ev.target.value }; }}>
        </div>
        <div class="ys-field">
          <label class="ys-label">Sensitivity ceiling</label>
          <select class="ys-select" .value=${e.sensitivity_ceiling || ''}
                  @change=${(ev) => { this._edit = { ...this._edit, sensitivity_ceiling: ev.target.value }; }}>
            <option value="">— unchanged —</option>
            ${SENSITIVITY_LEVELS.map((s) => html`<option value=${s}>${s}</option>`)}
          </select>
        </div>
        <div class="ys-field">
          <label class="ys-label">Disabled</label>
          <select class="ys-select" .value=${e.disabled ? 'true' : 'false'}
                  @change=${(ev) => { this._edit = { ...this._edit, disabled: ev.target.value === 'true' }; }}>
            <option value="false">active</option>
            <option value="true">disabled</option>
          </select>
        </div>
        <button class="ys-btn" @click=${() => this._saveEdit()}>Save (step-up)</button>
        <button class="ys-btn ys-btn-secondary" @click=${() => { this._edit = null; }}>Cancel</button>
      </div>
    </div>`;
  }

  _renderReset() {
    const r = this._reset;
    if (!r) return nothing;
    return html`<div class="ys-panel">
      <div class="ys-panel-header">Full reset — ${r.username}</div>
      <div class="ys-panel-body">
        <div class="ys-txt-note">Strips RBAC roles, sessions, API keys, TOTP and password. Re-enter YOUR admin TOTP to authorise.</div>
        <div class="ys-field">
          <label class="ys-label">Admin TOTP code</label>
          <input class="ys-input" inputmode="numeric" autocomplete="one-time-code" maxlength="8" pattern="[0-9]{6,8}"
                 .value=${r.totp_code || ''}
                 @input=${(ev) => { this._reset = { ...this._reset, totp_code: ev.target.value }; }}>
        </div>
        <button class="ys-btn ys-btn-danger" @click=${() => this._fullReset()}>Full reset</button>
        <button class="ys-btn ys-btn-secondary" @click=${() => { this._reset = null; }}>Cancel</button>
      </div>
    </div>`;
  }

  _renderRow(r) {
    return html`<tr>
      <td>${r.username}</td>
      <td>${r.email || ''}</td>
      <td>${r.disabled ? 'disabled' : 'active'}</td>
      <td>${yn(r.force_password_change)}</td>
      <td>${shortTs(r.created_at)}</td>
      <td>
        <button class="ys-btn ys-btn-ghost" @click=${() => { this._edit = { username: r.username, email: r.email || '', disabled: !!r.disabled, sensitivity_ceiling: '' }; }}>Edit</button>
        ${r.disabled
          ? html`<button class="ys-btn ys-btn-ghost" @click=${() => this._setDisabled(r.username, false)}>Enable</button>
                 <button class="ys-btn ys-btn-ghost" @click=${() => this._reactivate(r.username)}>Reactivate</button>`
          : html`<button class="ys-btn ys-btn-ghost" @click=${() => this._setDisabled(r.username, true)}>Disable</button>`}
        <button class="ys-btn ys-btn-ghost" @click=${() => this._issueApiKey(r.username)}>API key</button>
        <button class="ys-btn ys-btn-ghost" @click=${() => { this._reset = { username: r.username, totp_code: '' }; }}>Full reset</button>
        <button class="ys-btn ys-btn-danger" @click=${() => this._delete(r.username)}>Delete</button>
      </td>
    </tr>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading user accounts…</div></div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="users">
      <div class="ys-panel">
        <div class="ys-panel-header">Create user account</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Email</label>
            <input class="ys-input" type="email" .value=${this._new.email}
                   placeholder="user@example.com"
                   @input=${(e) => { this._new = { ...this._new, email: e.target.value }; }}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Username (optional)</label>
            <input class="ys-input" type="text" .value=${this._new.username}
                   @input=${(e) => { this._new = { ...this._new, username: e.target.value }; }}>
          </div>
          <button class="ys-btn" @click=${() => this._create()}>Create</button>
        </div>
      </div>
      ${this._renderEdit()}
      ${this._renderReset()}
      <div class="ys-panel">
        <div class="ys-panel-header">User accounts (${this._rows.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr>
              <th>Username</th><th>Email</th><th>Status</th><th>Force pwd</th>
              <th>Created</th><th>Actions</th>
            </tr></thead>
            <tbody>
              ${this._rows.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No user accounts.</td></tr>`
                : this._rows.map((r) => this._renderRow(r))}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-users', YsAdminUsers);

registerAdminModule({
  id: 'accounts',
  label: 'Admin accounts',
  icon: '👤',
  order: 0,
  group: 'identity',
  render: (ctx) => html`<ys-admin-accounts .api=${ctx.api} .app=${ctx.app}></ys-admin-accounts>`,
});

registerAdminModule({
  id: 'users',
  label: 'User accounts',
  icon: '🧑',
  order: 10,
  group: 'identity',
  render: (ctx) => html`<ys-admin-users .api=${ctx.api} .app=${ctx.app}></ys-admin-users>`,
});
