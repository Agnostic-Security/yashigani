// Yashigani 4.0 admin shell — Resource Permissions (unified grant) module.
//
// YSG-RISK-212: the unified Permission Grant admin surface existed since 3.1
// Phase 8 with a full working backend (routes/permissions.py) and an OLD
// static/js/permissions.js frontend (templates/dashboard.html #page-permissions,
// nav button "Permissions"), but was never ported to the ui4 admin SPA rebuild
// — no module file, no registerAdminModule() call, no admin-app.js import, so
// the whole surface was unreachable from the ui4 nav. Ava's Playwright suite
// proved the negative directly (src/tests/playwright/test_permissions_ui.py:
// `a[href='#permissions']`.count() == 0, every UI test SKIPped with an
// evidenced reason). This is the ui4 port.
//
// SAME CLASS OF GAP as YSG-RISK-163 (capability-policy — since ported, see
// modules/capability-policy.js) and YSG-RISK-213 (document sets — see
// documents-docopa.js::_renderSets()): backend shipped ahead of its ui4 port.
// This module follows capability-policy.js, its nearest sibling, in structure
// and idiom, and the module id is `permissions` so the nav renders
// `<a href="#permissions">` — the exact selector the existing Playwright suite
// already asserts on, which self-corrects the moment this lands.
//
// ── Backend contract (routes/permissions.py, mounted at /admin/api/permissions
//    by backoffice/app.py:1802) ─────────────────────────────────────────────
//   GET    /grants/{scope}/{scope_id}/{rt}                 AdminSession
//   PUT    /grants/{scope}/{scope_id}/{rt}/{rid}           StepUpAdminSession
//   DELETE /grants/{scope}/{scope_id}/{rt}/{rid}           StepUpAdminSession
//   GET    /effective?resource_type&resource_id&org_id
//                     &identity_id&group_ids               AdminSession
//   GET    /declarations                                   AdminSession
//   POST   /declarations                                   AdminSession (NOT surfaced — see below)
//   POST   /declarations/{rt}/{rid}/approve                StepUpAdminSession
//   DELETE /declarations/{rt}/{rid}                        StepUpAdminSession
//
// STEP-UP: every mutation above is StepUpAdminSession server-side. It is wired
// here the way nhi-approvals.js and documents-docopa.js do it — the client never
// decides what needs step-up (RISK-103); it calls ctx.api.mutate, the server
// answers 401 `step_up_required`, and the shared TOTP modal prompts, posts
// /auth/stepup and retries once (core/api-client.js:141-157). No un-gated
// mutation button ships here.
//
// DELIBERATELY NOT SURFACED — POST /declarations (submit a declaration). It is
// the only plain-AdminSession write on this router, and the legacy page never
// rendered a form for it either: declarations are raised by agent-manifest
// processing, the gateway/seeder, or the API — the admin's job in this view is
// the human-accountable DECIDE half (approve / reject), per EU AI Act Art.14.
// Porting the legacy information architecture faithfully means not inventing a
// "declare" form that never existed. Tracked as deliberate, not missing.
//
// MAKER≠CHECKER: approve enforces a distinct approver server-side (v4.1.2 bug 3
// — the declaring admin's SERVER-CAPTURED account_id, not the free-form
// declared_by string). We render `declared_by` only, exactly as the legacy page
// did, and surface the server's 403 `self_approval_forbidden` message verbatim
// rather than second-guessing the check client-side.
//
// 4.1 SEC-GAP-1: grants are keyed by identity_id (idnt_{12hex}), NOT email —
// the gateway enforcement path passes `identity_dict["identity_id"]` as
// principal_id (gateway/orchestrator.py:789,827). The legacy page's "User
// email" fields predate that and resolve against a key that is no longer used,
// so the same field slots here are labelled and sent as identity_id (the
// backend's own documented 4.1 contract; user_email remains accepted server-side
// as a deprecated alias). Same fields, corrected parameter — not a new IA.
//
// SAFE-RENDER: every rendered value (resource ids, opa_policy_ref, declared_by,
// justification, server error messages) is server- or operator-authored and is
// bound via Lit text-binding (textContent) — NEVER innerHTML, never the §3
// markdown sink. The legacy page hand-rolled escapeHtml() into innerHTML
// strings; that sink does not exist here at all.
//
// browser_capability is NOT managed here (the backend 422s it on every write on
// this router) — it lives in modules/capability-policy.js, mirroring the legacy
// page's own cross-reference.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

// Blast-radius resource types only — BLAST_RADIUS_TYPES in permissions/model.py.
const RT_LIST = ['mcp_server', 'external_api', 'cloud_model', 'agent'];
const RT_LABELS = {
  mcp_server: 'MCP Server',
  external_api: 'External API',
  cloud_model: 'Cloud Model',
  agent: 'Agent',
};

export class YsAdminPermissions extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _groups: { state: true },
    // Scope + resource-type picker (draft values; only committed to the
    // "active" fields below when Load grants is clicked, so the grants table
    // and its scope label can never disagree about what is on screen).
    _scopeType: { state: true },
    _scopeId: { state: true },
    _resourceType: { state: true },
    _activeScopeType: { state: true },
    _activeScopeId: { state: true },
    _activeResourceType: { state: true },
    _grants: { state: true },
    _grantsResult: { state: true },   // {ok, message} | null
    // Add/edit grant inline form
    _grantForm: { state: true },      // {open, rid, allow, opa, editing} | null
    _grantFormResult: { state: true },
    // Effective preview
    _eff: { state: true },            // draft inputs
    _effResult: { state: true },
    // Declarations
    _declarations: { state: true },
    _declResult: { state: true },
    _approveForm: { state: true },    // {rt, rid, allow, opa} | null
    _approveResult: { state: true },
    _busy: { state: true },           // in-flight mutation key, disables its button
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._groups = [];
    this._scopeType = 'org';
    this._scopeId = '';
    this._resourceType = 'mcp_server';
    this._activeScopeType = 'org';
    this._activeScopeId = 'default';
    this._activeResourceType = 'mcp_server';
    this._grants = [];
    this._grantsResult = null;
    this._grantForm = null;
    this._grantFormResult = null;
    this._eff = { rt: 'mcp_server', rid: '', org: 'default', identity: '', groups: '' };
    this._effResult = null;
    this._declarations = [];
    this._declResult = null;
    this._approveForm = null;
    this._approveResult = null;
    this._busy = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const g = await this.api.get('/admin/rbac/groups');
    this._groups = (g && Array.isArray(g.groups)) ? g.groups : [];
    await Promise.all([this._fetchGrants(), this._fetchDeclarations()]);
    this._loading = false;
  }

  // ── Scope resolution ──────────────────────────────────────────────────────

  /** Resolve the picker's scope_id, or null with a message if it is incomplete. */
  _resolveScopeId() {
    if (this._scopeType === 'org') return 'default';   // legacy: org scope is always "default"
    const v = (this._scopeId || '').trim();
    if (v) return v;
    return null;
  }

  _scopeIdPrompt() {
    if (this._scopeType === 'group') return 'Select a group first.';
    if (this._scopeType === 'user') return 'Enter a user identity ID first.';
    return 'Enter an agent ID first.';
  }

  _grantUrl(rid) {
    const base = '/admin/api/permissions/grants/'
      + `${encodeURIComponent(this._activeScopeType)}/`
      + `${encodeURIComponent(this._activeScopeId)}/`
      + `${encodeURIComponent(this._activeResourceType)}`;
    return rid === undefined ? base : `${base}/${encodeURIComponent(rid)}`;
  }

  _scopeLabel() {
    const rtLabel = RT_LABELS[this._activeResourceType] || this._activeResourceType;
    const scopePart = this._activeScopeType === 'org'
      ? 'Organisation'
      : `${this._activeScopeType.charAt(0).toUpperCase()}${this._activeScopeType.slice(1)}: ${this._activeScopeId}`;
    return `${rtLabel} — ${scopePart}`;
  }

  // ── Grants ────────────────────────────────────────────────────────────────

  async _fetchGrants() {
    const data = await this.api.get(this._grantUrl());
    if (!data) {
      this._grants = [];
      this._grantsResult = { ok: false, message: 'Could not load grants (the permission store may not be ready).' };
      return;
    }
    this._grants = Array.isArray(data.grants) ? data.grants : [];
    this._grantsResult = null;
  }

  async _onLoadGrants() {
    const scopeId = this._resolveScopeId();
    if (scopeId === null) {
      this._grantsResult = { ok: false, message: this._scopeIdPrompt() };
      return;
    }
    // Commit the draft picker values — the table and its label move together.
    this._activeScopeType = this._scopeType;
    this._activeScopeId = scopeId;
    this._activeResourceType = this._resourceType;
    this._grantForm = null;   // an open form belonged to the previous scope
    this._grantFormResult = null;
    await this._fetchGrants();
  }

  _onScopeTypeChange(e) {
    if (e.target.value === this._scopeType) return;
    this._scopeType = e.target.value;
    this._scopeId = '';           // a group id is not an agent id — never carry it across
    this._grantsResult = null;
  }

  _openGrantForm(g) {
    // g === undefined → "+ Add grant"; otherwise edit an existing row.
    this._grantForm = g
      ? { open: true, rid: g.resource_id, allow: !!g.allow, opa: g.opa_policy_ref || '', editing: true }
      : { open: true, rid: '', allow: true, opa: '', editing: false };
    this._grantFormResult = null;
  }

  _closeGrantForm() {
    this._grantForm = null;
    this._grantFormResult = null;
  }

  _setGrantForm(k, v) {
    this._grantForm = { ...this._grantForm, [k]: v };
  }

  /** INV-2 is enforced server-side (422 inv2_opa_policy_ref_required); mirrored
   *  here only for instant feedback, exactly as the legacy page did. */
  _inv2Missing(rt, allow, opa) {
    return rt === 'cloud_model' && allow && !(opa || '').trim();
  }

  async _saveGrant() {
    const f = this._grantForm;
    if (!f) return;
    const rid = (f.rid || '').trim();
    if (!rid) {
      this._grantFormResult = { ok: false, message: 'Resource ID is required.' };
      return;
    }
    if (this._inv2Missing(this._activeResourceType, f.allow, f.opa)) {
      this._grantFormResult = { ok: false, message: 'OPA policy ref is required for cloud_model with allow=on (INV-2).' };
      return;
    }
    const body = { allow: !!f.allow };
    const opa = (f.opa || '').trim();
    if (opa) body.opa_policy_ref = opa;

    this._busy = `grant:${rid}`;
    // StepUpAdminSession server-side — the TOTP modal fires from api-client's
    // step_up_required interceptor; nothing to do here (RISK-103).
    const res = await this.api.mutate(this._grantUrl(rid), { method: 'PUT', body });
    this._busy = '';
    if (res.ok) {
      this._grantForm = null;
      this._grantFormResult = null;
      this._grantsResult = { ok: true, message: 'Grant saved.' };
      this.app && this.app.toast('Permission grant saved.', 'success');
      await this._fetchGrants();
      // _fetchGrants() clears _grantsResult on success — restore the badge.
      this._grantsResult = { ok: true, message: 'Grant saved.' };
    } else {
      this._grantFormResult = { ok: false, message: (res.error && res.error.message) || 'Save failed.' };
    }
  }

  async _deleteGrant(rid) {
    if (!rid) return;
    if (!confirm(`Delete grant for "${rid}"? This removes the explicit permission entry.`)) return;
    this._busy = `grant:${rid}`;
    const res = await this.api.mutate(this._grantUrl(rid), { method: 'DELETE' });
    this._busy = '';
    if (res.ok) {
      this.app && this.app.toast('Permission grant deleted.', 'success');
      await this._fetchGrants();
      this._grantsResult = { ok: true, message: 'Grant deleted.' };
    } else {
      this._grantsResult = { ok: false, message: (res.error && res.error.message) || 'Delete failed.' };
    }
  }

  // ── Effective preview ─────────────────────────────────────────────────────

  _setEff(k, v) { this._eff = { ...this._eff, [k]: v }; }

  async _resolveEffective() {
    const e = this._eff;
    const rid = (e.rid || '').trim();
    if (!rid) {
      this._effResult = { ok: false, message: 'Enter a resource ID.' };
      return;
    }
    let qs = `?resource_type=${encodeURIComponent(e.rt)}`
      + `&resource_id=${encodeURIComponent(rid)}`
      + `&org_id=${encodeURIComponent((e.org || '').trim() || 'default')}`;
    // 4.1 SEC-GAP-1: identity_id is the grant key; user_email is the deprecated alias.
    const identity = (e.identity || '').trim();
    if (identity) qs += `&identity_id=${encodeURIComponent(identity)}`;
    const groups = (e.groups || '').trim();
    if (groups) qs += `&group_ids=${encodeURIComponent(groups)}`;

    const data = await this.api.get(`/admin/api/permissions/effective${qs}`);
    if (!data) {
      this._effResult = { ok: false, message: 'Failed to resolve (the permission store may not be ready).' };
      return;
    }
    this._effResult = { ok: true, data };
  }

  // ── Declarations ──────────────────────────────────────────────────────────

  async _fetchDeclarations() {
    const data = await this.api.get('/admin/api/permissions/declarations');
    if (!data) {
      this._declarations = [];
      this._declResult = { ok: false, message: 'Could not load declarations.' };
      return;
    }
    this._declarations = Array.isArray(data.pending) ? data.pending : [];
    this._declResult = null;
  }

  _openApprove(d) {
    this._approveForm = { rt: d.resource_type, rid: d.resource_id, allow: true, opa: '' };
    this._approveResult = null;
  }

  _closeApprove() {
    this._approveForm = null;
    this._approveResult = null;
  }

  _setApprove(k, v) { this._approveForm = { ...this._approveForm, [k]: v }; }

  async _approveDeclaration() {
    const f = this._approveForm;
    if (!f) return;
    if (this._inv2Missing(f.rt, f.allow, f.opa)) {
      this._approveResult = { ok: false, message: 'OPA policy ref is required for cloud_model with allow=on (INV-2).' };
      return;
    }
    const body = { allow: !!f.allow };
    const opa = (f.opa || '').trim();
    if (opa) body.opa_policy_ref = opa;

    const url = '/admin/api/permissions/declarations/'
      + `${encodeURIComponent(f.rt)}/${encodeURIComponent(f.rid)}/approve`;

    this._busy = `decl:${f.rt}:${f.rid}`;
    // StepUpAdminSession + server-side distinct-approver check. A 403
    // `self_approval_forbidden` is surfaced verbatim — the maker identity is
    // deliberately not exposed to the client, so the server is the only place
    // that can make (or explain) that call.
    const res = await this.api.mutate(url, { method: 'POST', body });
    this._busy = '';
    if (res.ok) {
      this._approveForm = null;
      this._approveResult = null;
      this._declResult = { ok: true, message: 'Approved. Org-level grant created.' };
      this.app && this.app.toast('Declaration approved — org-level grant created.', 'success');
      await this._fetchDeclarations();
      this._declResult = { ok: true, message: 'Approved. Org-level grant created.' };
      // Refresh the grants table if the approved type is the one on screen.
      if (f.rt === this._activeResourceType) await this._fetchGrants();
    } else {
      this._approveResult = { ok: false, message: (res.error && res.error.message) || 'Approval failed.' };
    }
  }

  async _rejectDeclaration(d) {
    const label = `${RT_LABELS[d.resource_type] || d.resource_type} / ${d.resource_id}`;
    if (!confirm(`Reject declaration for "${label}"?\nNo grant will be created.`)) return;
    const url = '/admin/api/permissions/declarations/'
      + `${encodeURIComponent(d.resource_type)}/${encodeURIComponent(d.resource_id)}`;
    this._busy = `decl:${d.resource_type}:${d.resource_id}`;
    const res = await this.api.mutate(url, { method: 'DELETE' });
    this._busy = '';
    if (res.ok) {
      this.app && this.app.toast('Declaration rejected.', 'success');
      await this._fetchDeclarations();
      this._declResult = { ok: true, message: 'Declaration rejected.' };
    } else {
      this._declResult = { ok: false, message: (res.error && res.error.message) || 'Reject failed.' };
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  _renderResult(r) {
    if (!r) return nothing;
    return html`<div class="ys-badge ${r.ok ? 'ys-badge-green' : 'ys-badge-red'}">${r.message}</div>`;
  }

  _renderScopePanel() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Scope &amp; resource type</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Explicit allow/deny grants for blast-radius resource types (MCP servers,
            external APIs, cloud models, agents). The org grant is the ceiling —
            groups, users and agents may only narrow it, never widen it.
            Browser Permissions-Policy is managed on the Capability Policy page.
          </div>
          <div class="ys-admin-2col">
            <div class="ys-field">
              <label class="ys-label">Scope type</label>
              <select class="ys-select" id="perm-scope-type" .value=${this._scopeType}
                @change=${(e) => this._onScopeTypeChange(e)}>
                <option value="org">Organisation</option>
                <option value="group">Group</option>
                <option value="user">User</option>
                <option value="agent">Agent</option>
              </select>
            </div>
            <div class="ys-field">
              <label class="ys-label">Resource type</label>
              <select class="ys-select" id="perm-resource-type" .value=${this._resourceType}
                @change=${(e) => { this._resourceType = e.target.value; }}>
                ${RT_LIST.map((rt) => html`<option value=${rt}>${RT_LABELS[rt]}</option>`)}
              </select>
            </div>
          </div>
          ${this._scopeType === 'group' ? html`
            <div class="ys-field" id="perm-group-picker">
              <label class="ys-label">Group</label>
              <select class="ys-select" id="perm-group-id" .value=${this._scopeId}
                @change=${(e) => { this._scopeId = e.target.value; }}>
                <option value="">${this._groups.length ? 'Select a group…' : 'No groups configured'}</option>
                ${this._groups.map((g) => html`<option value=${g.id}>${g.display_name || g.id} (${g.id})</option>`)}
              </select>
            </div>` : nothing}
          ${this._scopeType === 'user' ? html`
            <div class="ys-field" id="perm-user-picker">
              <label class="ys-label">User identity ID</label>
              <input class="ys-input" id="perm-user-id" type="text" placeholder="idnt_0123456789ab"
                .value=${this._scopeId} @input=${(e) => { this._scopeId = e.target.value; }}>
              <span class="ys-txt-note">4.1 SEC-GAP-1: user grants are keyed by identity_id, not email.</span>
            </div>` : nothing}
          ${this._scopeType === 'agent' ? html`
            <div class="ys-field" id="perm-agent-picker">
              <label class="ys-label">Agent ID</label>
              <input class="ys-input" id="perm-agent-id" type="text" placeholder="agent-id"
                .value=${this._scopeId} @input=${(e) => { this._scopeId = e.target.value; }}>
            </div>` : nothing}
          <button class="ys-btn" id="perm-scope-load" @click=${() => this._onLoadGrants()}>Load grants</button>
        </div>
      </div>`;
  }

  _renderGrantForm() {
    const f = this._grantForm;
    if (!f || !f.open) return nothing;
    const showOpa = this._activeResourceType === 'cloud_model' && f.allow;
    return html`
      <div class="ys-panel" id="perm-grant-form">
        <div class="ys-panel-header" id="perm-grant-form-title">
          ${f.editing ? `Edit grant: ${f.rid}` : 'Add grant'} — step-up required
        </div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">Resource ID</label>
            <input class="ys-input" id="perm-grant-rid" type="text" ?disabled=${f.editing}
              placeholder="server-id / api-host / model-name / agent-id"
              .value=${f.rid} @input=${(e) => this._setGrantForm('rid', e.target.value)}>
          </div>
          <label class="ys-svc-card">
            <input type="checkbox" id="perm-grant-allow" ?checked=${f.allow}
              @change=${(e) => this._setGrantForm('allow', e.target.checked)}>
            <span class="ys-svc-name">Allow (unchecked = explicit deny / narrow)</span>
          </label>
          ${showOpa ? html`
            <div class="ys-field" id="perm-grant-opa-row">
              <label class="ys-label">OPA policy ref (required for cloud_model + allow — INV-2)</label>
              <input class="ys-input" id="perm-grant-opa" type="text" placeholder="yashigani/cloud_model/gpt4o"
                .value=${f.opa} @input=${(e) => this._setGrantForm('opa', e.target.value)}>
            </div>` : nothing}
          ${this._renderResult(this._grantFormResult)}
          <button class="ys-btn" id="perm-grant-save"
            ?disabled=${this._busy === `grant:${(f.rid || '').trim()}`}
            @click=${() => this._saveGrant()}>Save grant</button>
          <button class="ys-btn ys-btn-ghost" id="perm-grant-cancel"
            @click=${() => this._closeGrantForm()}>Cancel</button>
        </div>
      </div>`;
  }

  _renderGrants() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Grants — <span id="perm-scope-label">${this._scopeLabel()}</span>
          <button class="ys-btn ys-btn-ghost" id="perm-grant-add"
            @click=${() => this._openGrantForm()}>+ Add grant</button>
        </div>
        <div class="ys-panel-body" id="perm-grants-container">
          <table class="ys-table">
            <thead><tr><th>Resource ID</th><th>Grant</th><th>OPA policy ref</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._grants.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="4">No grants for this scope and resource type.</td></tr>`
                : this._grants.map((g) => html`
                    <tr>
                      <td><code>${g.resource_id}</code></td>
                      <td><span class="ys-badge ${g.allow ? 'ys-badge-green' : 'ys-badge-red'}">${g.allow ? 'allow' : 'deny'}</span></td>
                      <td>${g.opa_policy_ref ? html`<code>${g.opa_policy_ref}</code>` : '—'}</td>
                      <td>
                        <button class="ys-btn ys-btn-ghost" data-act="edit"
                          @click=${() => this._openGrantForm(g)}>Edit</button>
                        <button class="ys-btn ys-btn-danger" data-act="delete"
                          ?disabled=${this._busy === `grant:${g.resource_id}`}
                          @click=${() => this._deleteGrant(g.resource_id)}>Delete</button>
                      </td>
                    </tr>`)}
            </tbody>
          </table>
          <div id="perm-grants-result">${this._renderResult(this._grantsResult)}</div>
        </div>
      </div>`;
  }

  _renderEffPath(data) {
    const path = data.resolution_path || {};
    const rows = [
      { label: 'Org grant', grant: path.org_grant },
      ...(path.group_grants || []).map((gg) => ({ label: `Group: ${gg.group_id}`, grant: gg })),
    ];
    if (data.identity_id) rows.push({ label: 'User grant', grant: path.user_grant });
    return html`
      <table class="ys-table" id="perm-eff-path">
        <thead><tr><th>Tier</th><th>Grant</th><th>OPA policy ref</th></tr></thead>
        <tbody>
          ${rows.map((r) => html`
            <tr>
              <td>${r.label}</td>
              <td>${r.grant
                ? html`<span class="ys-badge ${r.grant.allow ? 'ys-badge-green' : 'ys-badge-red'}">${r.grant.allow ? 'allow' : 'deny'}</span>`
                : html`<span class="ys-txt-note">no explicit grant — deny by default</span>`}</td>
              <td>${r.grant && r.grant.opa_policy_ref ? html`<code>${r.grant.opa_policy_ref}</code>` : '—'}</td>
            </tr>`)}
          <tr>
            <td><strong>Effective</strong></td>
            <td><span class="ys-badge ${data.effective_allow ? 'ys-badge-green' : 'ys-badge-red'}">${data.effective_allow ? 'ALLOW' : 'DENY'}</span></td>
            <td>—</td>
          </tr>
        </tbody>
      </table>`;
  }

  _renderEffective() {
    const e = this._eff;
    const r = this._effResult;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Effective permission (resolved)</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Resolve the effective permission for a subject + resource after the
            org-ceiling rules (INV-1 / INV-3). Uses the same resolver as the
            gateway enforcement path.
          </div>
          <div class="ys-admin-2col">
            <div class="ys-field">
              <label class="ys-label">Resource type</label>
              <select class="ys-select" id="perm-eff-rt" .value=${e.rt}
                @change=${(ev) => this._setEff('rt', ev.target.value)}>
                ${RT_LIST.map((rt) => html`<option value=${rt}>${RT_LABELS[rt]}</option>`)}
              </select>
            </div>
            <div class="ys-field">
              <label class="ys-label">Resource ID</label>
              <input class="ys-input" id="perm-eff-rid" type="text" placeholder="server-id / host / model"
                .value=${e.rid} @input=${(ev) => this._setEff('rid', ev.target.value)}>
            </div>
          </div>
          <div class="ys-admin-2col">
            <div class="ys-field">
              <label class="ys-label">Org ID</label>
              <input class="ys-input" id="perm-eff-org" type="text"
                .value=${e.org} @input=${(ev) => this._setEff('org', ev.target.value)}>
            </div>
            <div class="ys-field">
              <label class="ys-label">User identity ID (optional)</label>
              <input class="ys-input" id="perm-eff-identity" type="text" placeholder="idnt_0123456789ab"
                .value=${e.identity} @input=${(ev) => this._setEff('identity', ev.target.value)}>
            </div>
          </div>
          <div class="ys-field">
            <label class="ys-label">Group IDs (comma-separated, optional)</label>
            <input class="ys-input" id="perm-eff-groups" type="text" placeholder="group1,group2"
              .value=${e.groups} @input=${(ev) => this._setEff('groups', ev.target.value)}>
          </div>
          <button class="ys-btn" id="perm-eff-resolve" @click=${() => this._resolveEffective()}>Resolve</button>
          <div id="perm-eff-result">
            ${r ? (r.ok ? html`
              <div class="ys-badge ${r.data.effective_allow ? 'ys-badge-green' : 'ys-badge-red'}">
                ${r.data.effective_allow ? 'ALLOW' : 'DENY'}
              </div>
              <div class="ys-txt-note">
                ${RT_LABELS[r.data.resource_type] || r.data.resource_type} /
                <code>${r.data.resource_id}</code> (org: ${r.data.org_id || 'default'})
              </div>
              ${this._renderEffPath(r.data)}`
              : html`<div class="ys-badge ys-badge-red">${r.message}</div>`) : nothing}
          </div>
        </div>
      </div>`;
  }

  _renderApproveForm() {
    const f = this._approveForm;
    if (!f) return nothing;
    const showOpa = f.rt === 'cloud_model' && f.allow;
    return html`
      <div class="ys-panel" id="perm-decl-approve-form">
        <div class="ys-panel-header">Approve declaration — step-up required</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">
            Approving creates an org-level grant. This is the human-accountable act
            (EU AI Act Art.14 / ASVS V10.3.5) and is written to the tamper-evident
            audit chain. A DIFFERENT admin from the one who declared it must approve.
          </div>
          <div class="ys-field">
            <label class="ys-label">Resource</label>
            <strong id="perm-decl-approve-label">${RT_LABELS[f.rt] || f.rt}: ${f.rid}</strong>
          </div>
          <label class="ys-svc-card">
            <input type="checkbox" id="perm-decl-approve-allow" ?checked=${f.allow}
              @change=${(e) => this._setApprove('allow', e.target.checked)}>
            <span class="ys-svc-name">Allow (unchecked = grant an explicit org-level deny)</span>
          </label>
          ${showOpa ? html`
            <div class="ys-field" id="perm-decl-approve-opa-row">
              <label class="ys-label">OPA policy ref (required for cloud_model + allow — INV-2)</label>
              <input class="ys-input" id="perm-decl-approve-opa" type="text" placeholder="yashigani/cloud_model/gpt4o"
                .value=${f.opa} @input=${(e) => this._setApprove('opa', e.target.value)}>
            </div>` : nothing}
          ${this._renderResult(this._approveResult)}
          <button class="ys-btn" id="perm-decl-approve-confirm"
            ?disabled=${this._busy === `decl:${f.rt}:${f.rid}`}
            @click=${() => this._approveDeclaration()}>Confirm approval</button>
          <button class="ys-btn ys-btn-ghost" id="perm-decl-approve-cancel"
            @click=${() => this._closeApprove()}>Cancel</button>
        </div>
      </div>`;
  }

  _renderDeclarations() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Pending declarations (${this._declarations.length})
          <button class="ys-btn ys-btn-ghost" id="perm-decl-refresh"
            @click=${() => this._fetchDeclarations()}>Refresh</button>
        </div>
        <div class="ys-panel-body" id="perm-decl-container">
          <div class="ys-txt-note">
            Agent manifests, the gateway/seeder and operators declare resources they
            need access to. An admin must approve to create the org-level grant
            (human-in-the-loop). Declarations are submitted via the API, not from
            this page.
          </div>
          <table class="ys-table">
            <thead><tr><th>Resource type</th><th>Resource ID</th><th>Declared by</th><th>Justification</th><th>Org grant</th><th>Actions</th></tr></thead>
            <tbody>
              ${this._declarations.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No pending declarations.</td></tr>`
                : this._declarations.map((d) => html`
                    <tr>
                      <td><span class="ys-badge ys-badge-blue">${RT_LABELS[d.resource_type] || d.resource_type}</span></td>
                      <td><code>${d.resource_id}</code></td>
                      <td>${d.declared_by || '—'}</td>
                      <td>${d.justification || '—'}</td>
                      <td><span class="ys-badge ${d.org_grant_exists ? 'ys-badge-green' : 'ys-badge-red'}">${d.org_grant_exists ? 'exists' : 'none'}</span></td>
                      <td>
                        <button class="ys-btn" data-act="approve"
                          @click=${() => this._openApprove(d)}>Approve</button>
                        <button class="ys-btn ys-btn-danger" data-act="reject"
                          ?disabled=${this._busy === `decl:${d.resource_type}:${d.resource_id}`}
                          @click=${() => this._rejectDeclaration(d)}>Reject</button>
                      </td>
                    </tr>`)}
            </tbody>
          </table>
          <div id="perm-decl-result">${this._renderResult(this._declResult)}</div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading resource permissions…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderScopePanel()}
        ${this._renderGrantForm()}
        ${this._renderGrants()}
        ${this._renderEffective()}
        ${this._renderApproveForm()}
        ${this._renderDeclarations()}
      </div>`;
  }
}

customElements.define('ys-admin-permissions', YsAdminPermissions);

registerAdminModule({
  id: 'permissions',          // nav renders <a href="#permissions"> — the selector
                              // test_permissions_ui.py already asserts on.
  label: 'Resource Permissions',
  icon: '🎫',
  order: 6,                   // immediately after Capability Policy (order 5) in the
                              // Governance group — the legacy nav placed "Permissions"
                              // directly after "Permissions Policy" and the two pages
                              // cross-reference each other.
  group: 'governance',
  render: (ctx) => html`<ys-admin-permissions .api=${ctx.api} .app=${ctx.app}></ys-admin-permissions>`,
});
