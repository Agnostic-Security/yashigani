// Yashigani 4.0 admin shell — Identity & Access: RBAC + SCIM module group.
//
// Two nav sections registered from this file:
//   • #rbac — Access control / RBAC groups (routes/rbac.py + rbac_sources.py,
//             prefix /admin/rbac)
//   • #scim — SCIM 2.0 provisioning (routes/scim.py, prefix /scim/v2)
//
// RISK-103 STEP-UP RE-TIER (client-enforced): the RBAC group/member mutations,
// the RBAC OPA force-push, and ALL SCIM interactive writes are served by routes
// that still carry a plain AdminSession, so the ApiClient's server-driven
// step-up never fires for them. Each such mutation is gated through elevate()
// (_iam.js) — it raises the shared TOTP modal and elevates the session via
// /auth/stepup BEFORE the write, so none of these is a one-click action.
//
// TRUSTED-CHROME: all values are server-authored RBAC/SCIM config shown via Lit
// auto-escape; the §3 markdown sink is never used.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';
import { elevate, reportMutate } from './_iam.js';

void widgets;

// ── RBAC ─────────────────────────────────────────────────────────────────────
export class YsAdminRbac extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _groups: { state: true },
    _paths: { state: true },
    _methods: { state: true },
    _draftName: { state: true },
    _draftResources: { state: true },   // [{method, path_glob}]
    _draftMethod: { state: true },
    _draftPath: { state: true },
    _sel: { state: true },              // selected group for member management
    _newMember: { state: true },
    _renameTo: { state: true },         // pending display_name edit (RB-04)
    _lookupEmail: { state: true },      // per-user group lookup (RB-08)
    _lookupResult: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._groups = [];
    this._paths = [];
    this._methods = [];
    this._draftName = '';
    this._draftResources = [];
    this._draftMethod = '*';
    this._draftPath = '';
    this._sel = null;
    this._newMember = '';
    this._renameTo = '';
    this._lookupEmail = '';
    this._lookupResult = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [groups, paths, methods] = await Promise.all([
      this.api.get('/admin/rbac/groups'),
      this.api.get('/admin/rbac/sources/paths'),
      this.api.get('/admin/rbac/sources/methods'),
    ]);
    this._groups = Array.isArray(groups) ? groups : (groups && Array.isArray(groups.groups) ? groups.groups : []);
    this._paths = (paths && Array.isArray(paths.paths)) ? paths.paths : [];
    this._methods = (methods && Array.isArray(methods.methods)) ? methods.methods : [];
    // keep selection fresh after reload
    if (this._sel) {
      this._sel = this._groups.find((g) => g.id === this._sel.id) || null;
    }
    this._loading = false;
  }

  _addDraftResource() {
    const path_glob = (this._draftPath || '').trim();
    if (!path_glob) { this.app && this.app.toast('Choose a path pattern.', 'error'); return; }
    this._draftResources = [...this._draftResources, { method: this._draftMethod || '*', path_glob }];
    this._draftPath = '';
  }

  async _createGroup() {
    const display_name = (this._draftName || '').trim();
    if (!display_name) { this.app && this.app.toast('Group name is required.', 'error'); return; }
    if (!(await elevate(this.api, 'Creating an RBAC group changes access policy — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate('/admin/rbac/groups', {
      method: 'POST',
      body: { display_name, allowed_resources: this._draftResources },
    });
    if (reportMutate(this.app, res, 'RBAC group created.')) {
      this._draftName = '';
      this._draftResources = [];
      await this._load();
    }
  }

  async _deleteGroup(id) {
    if (!(await elevate(this.api, 'Deleting an RBAC group changes access policy — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(`/admin/rbac/groups/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'RBAC group deleted.')) {
      if (this._sel && this._sel.id === id) this._sel = null;
      await this._load();
    }
  }

  async _addMember(id) {
    const email = (this._newMember || '').trim();
    if (!email) { this.app && this.app.toast('Member email is required.', 'error'); return; }
    if (!(await elevate(this.api, 'Adding a group member changes access policy — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(`/admin/rbac/groups/${encodeURIComponent(id)}/members`, {
      method: 'POST', body: { email },
    });
    if (reportMutate(this.app, res, 'Member added.')) {
      this._newMember = '';
      await this._load();
    }
  }

  async _removeMember(id, email) {
    if (!(await elevate(this.api, 'Removing a group member changes access policy — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(
      `/admin/rbac/groups/${encodeURIComponent(id)}/members/${encodeURIComponent(email)}`,
      { method: 'DELETE' },
    );
    if (reportMutate(this.app, res, 'Member removed.')) await this._load();
  }

  async _renameGroup(id) {
    const display_name = (this._renameTo || '').trim();
    if (!display_name) { this.app && this.app.toast('New name is required.', 'error'); return; }
    if (!(await elevate(this.api, 'Renaming an RBAC group changes access policy — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(`/admin/rbac/groups/${encodeURIComponent(id)}`, {
      method: 'PUT', body: { display_name },
    });
    if (reportMutate(this.app, res, 'RBAC group updated.')) {
      this._renameTo = '';
      await this._load();
    }
  }

  async _lookup() {
    const email = (this._lookupEmail || '').trim();
    if (!email) { this.app && this.app.toast('Enter an email to look up.', 'error'); return; }
    const data = await this.api.get(`/admin/rbac/users/${encodeURIComponent(email)}/groups`);
    this._lookupResult = data || { email, groups: [] };
  }

  async _forcePush() {
    if (!(await elevate(this.api, 'Force-pushing RBAC policy to OPA is a dangerous action — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate('/admin/rbac/policy/push', { method: 'POST' });
    reportMutate(this.app, res, 'RBAC policy pushed to OPA.');
  }

  _renderSelected() {
    const g = this._sel;
    if (!g) return nothing;
    const members = Array.isArray(g.members) ? g.members : [];
    const resources = Array.isArray(g.allowed_resources) ? g.allowed_resources : [];
    return html`<div class="ys-panel">
      <div class="ys-panel-header">Group — ${g.display_name} (${g.id})</div>
      <div class="ys-panel-body">
        <div class="ys-field">
          <label class="ys-label">Rename group (display name)</label>
          <input class="ys-input" type="text" .value=${this._renameTo}
                 placeholder=${g.display_name}
                 @input=${(e) => { this._renameTo = e.target.value; }}>
        </div>
        <button class="ys-btn" @click=${() => this._renameGroup(g.id)}>Save name (step-up)</button>
        <div class="ys-txt-note">Allowed resources</div>
        <table class="ys-table">
          <thead><tr><th>Method</th><th>Path glob</th></tr></thead>
          <tbody>
            ${resources.length === 0
              ? html`<tr><td class="ys-table-empty" colspan="2">No resource grants.</td></tr>`
              : resources.map((r) => html`<tr><td>${r.method || '*'}</td><td>${r.path_glob || r.path || ''}</td></tr>`)}
          </tbody>
        </table>
        <div class="ys-txt-note">Members (${members.length})</div>
        <table class="ys-table">
          <thead><tr><th>Email</th><th>Actions</th></tr></thead>
          <tbody>
            ${members.length === 0
              ? html`<tr><td class="ys-table-empty" colspan="2">No members.</td></tr>`
              : members.map((m) => html`<tr>
                  <td>${m}</td>
                  <td><button class="ys-btn ys-btn-danger" @click=${() => this._removeMember(g.id, m)}>Remove (step-up)</button></td>
                </tr>`)}
          </tbody>
        </table>
        <div class="ys-field">
          <label class="ys-label">Add member email</label>
          <input class="ys-input" type="email" .value=${this._newMember}
                 @input=${(e) => { this._newMember = e.target.value; }}>
        </div>
        <button class="ys-btn" @click=${() => this._addMember(g.id)}>Add member (step-up)</button>
        <button class="ys-btn ys-btn-secondary" @click=${() => { this._sel = null; }}>Close</button>
      </div>
    </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading RBAC…</div></div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="rbac">
      <div class="ys-panel">
        <div class="ys-panel-header">OPA policy</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">Re-push the current RBAC data to the OPA decision point.</div>
          <button class="ys-btn ys-btn-danger" data-act="force-push" @click=${() => this._forcePush()}>Force push to OPA (step-up)</button>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">Create RBAC group</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Display name</label>
            <input class="ys-input" type="text" .value=${this._draftName}
                   @input=${(e) => { this._draftName = e.target.value; }}>
          </div>
          <div class="ys-field">
            <label class="ys-label">Resource: method</label>
            <select class="ys-select" .value=${this._draftMethod}
                    @change=${(e) => { this._draftMethod = e.target.value; }}>
              <option value="*">* (any)</option>
              ${this._methods.map((m) => html`<option value=${m.method}>${m.method} — ${m.label || ''}</option>`)}
            </select>
          </div>
          <div class="ys-field">
            <label class="ys-label">Resource: path glob</label>
            <select class="ys-select" .value=${this._draftPath}
                    @change=${(e) => { this._draftPath = e.target.value; }}>
              <option value="">— select —</option>
              ${this._paths.map((p) => html`<option value=${p.glob}>${p.glob} (${p.risk || 'n/a'})</option>`)}
            </select>
          </div>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._addDraftResource()}>Add resource</button>
          <table class="ys-table">
            <thead><tr><th>Method</th><th>Path glob</th></tr></thead>
            <tbody>
              ${this._draftResources.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="2">No staged grants — group will start with no access.</td></tr>`
                : this._draftResources.map((r) => html`<tr><td>${r.method}</td><td>${r.path_glob}</td></tr>`)}
            </tbody>
          </table>
          <button class="ys-btn" @click=${() => this._createGroup()}>Create group (step-up)</button>
        </div>
      </div>

      ${this._renderSelected()}

      <div class="ys-panel">
        <div class="ys-panel-header">User group membership</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">User email</label>
            <input class="ys-input" type="email" .value=${this._lookupEmail}
                   @input=${(e) => { this._lookupEmail = e.target.value; }}>
          </div>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._lookup()}>Look up groups</button>
          ${this._lookupResult
            ? html`<table class="ys-table">
                <thead><tr><th>Group</th><th>ID</th></tr></thead>
                <tbody>
                  ${(this._lookupResult.groups || []).length === 0
                    ? html`<tr><td class="ys-table-empty" colspan="2">No group memberships for ${this._lookupResult.email}.</td></tr>`
                    : this._lookupResult.groups.map((g) => html`<tr><td>${g.display_name}</td><td>${g.id}</td></tr>`)}
                </tbody>
              </table>`
            : nothing}
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">RBAC groups (${this._groups.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>Name</th><th>ID</th><th>Members</th><th>Grants</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._groups.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="5">No RBAC groups.</td></tr>`
                : this._groups.map((g) => html`<tr>
                    <td>${g.display_name}</td>
                    <td>${g.id}</td>
                    <td>${Array.isArray(g.members) ? g.members.length : 0}</td>
                    <td>${Array.isArray(g.allowed_resources) ? g.allowed_resources.length : 0}</td>
                    <td>
                      <button class="ys-btn ys-btn-ghost" @click=${() => { this._sel = g; this._newMember = ''; }}>Manage</button>
                      <button class="ys-btn ys-btn-danger" @click=${() => this._deleteGroup(g.id)}>Delete (step-up)</button>
                    </td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-rbac', YsAdminRbac);

// ── SCIM ─────────────────────────────────────────────────────────────────────
export class YsAdminScim extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _users: { state: true },
    _groups: { state: true },
    _newUser: { state: true },
    _newGroup: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._users = [];
    this._groups = [];
    this._newUser = '';
    this._newGroup = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [users, groups] = await Promise.all([
      this.api.get('/scim/v2/Users'),
      this.api.get('/scim/v2/Groups'),
    ]);
    this._users = (users && Array.isArray(users.Resources)) ? users.Resources : [];
    this._groups = (groups && Array.isArray(groups.Resources)) ? groups.Resources : [];
    this._loading = false;
  }

  async _provision() {
    const userName = (this._newUser || '').trim();
    if (!userName) { this.app && this.app.toast('userName (email) is required.', 'error'); return; }
    if (!(await elevate(this.api, 'SCIM user provisioning is an interactive write — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate('/scim/v2/Users', { method: 'POST', body: { userName, active: true } });
    if (reportMutate(this.app, res, 'SCIM user provisioned.')) {
      this._newUser = '';
      await this._load();
    }
  }

  async _deprovision(id) {
    if (!(await elevate(this.api, 'SCIM deprovisioning is an interactive write — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(`/scim/v2/Users/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'SCIM user deprovisioned.')) await this._load();
  }

  async _createGroup() {
    const displayName = (this._newGroup || '').trim();
    if (!displayName) { this.app && this.app.toast('displayName is required.', 'error'); return; }
    if (!(await elevate(this.api, 'SCIM group creation is an interactive write — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate('/scim/v2/Groups', { method: 'POST', body: { displayName } });
    if (reportMutate(this.app, res, 'SCIM group created.')) {
      this._newGroup = '';
      await this._load();
    }
  }

  async _deleteGroup(id) {
    if (!(await elevate(this.api, 'SCIM group deletion is an interactive write — step-up required.'))) {
      this.app && this.app.toast('Step-up cancelled.', 'error');
      return;
    }
    const res = await this.api.mutate(`/scim/v2/Groups/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (reportMutate(this.app, res, 'SCIM group deleted.')) await this._load();
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading SCIM…</div></div>`;
    }
    return html`<div class="ys-admin-content-pad" data-module="scim">
      <div class="ys-panel">
        <div class="ys-panel-header">Provision SCIM user</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">userName (email)</label>
            <input class="ys-input" type="email" .value=${this._newUser}
                   @input=${(e) => { this._newUser = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._provision()}>Provision (step-up)</button>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">SCIM users (${this._users.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>userName</th><th>Active</th><th>Groups</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._users.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="4">No SCIM users.</td></tr>`
                : this._users.map((u) => html`<tr>
                    <td>${u.userName || u.id}</td>
                    <td>${u.active ? 'yes' : 'no'}</td>
                    <td>${Array.isArray(u.groups) ? u.groups.length : 0}</td>
                    <td><button class="ys-btn ys-btn-danger" @click=${() => this._deprovision(u.id)}>Deprovision (step-up)</button></td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">Create SCIM group</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">displayName</label>
            <input class="ys-input" type="text" .value=${this._newGroup}
                   @input=${(e) => { this._newGroup = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._createGroup()}>Create group (step-up)</button>
        </div>
      </div>

      <div class="ys-panel">
        <div class="ys-panel-header">SCIM groups (${this._groups.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>displayName</th><th>ID</th><th>Members</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._groups.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="4">No SCIM groups.</td></tr>`
                : this._groups.map((g) => html`<tr>
                    <td>${g.displayName || g.id}</td>
                    <td>${g.id}</td>
                    <td>${Array.isArray(g.members) ? g.members.length : 0}</td>
                    <td><button class="ys-btn ys-btn-danger" @click=${() => this._deleteGroup(g.id)}>Delete (step-up)</button></td>
                  </tr>`)}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
  }
}
customElements.define('ys-admin-scim', YsAdminScim);

registerAdminModule({
  id: 'rbac',
  label: 'Access control',
  icon: '🔐',
  order: 20,
  group: 'identity',
  render: (ctx) => html`<ys-admin-rbac .api=${ctx.api} .app=${ctx.app}></ys-admin-rbac>`,
});

registerAdminModule({
  id: 'scim',
  label: 'SCIM provisioning',
  icon: '🔁',
  order: 30,
  group: 'identity',
  render: (ctx) => html`<ys-admin-scim .api=${ctx.api} .app=${ctx.app}></ys-admin-scim>`,
});
