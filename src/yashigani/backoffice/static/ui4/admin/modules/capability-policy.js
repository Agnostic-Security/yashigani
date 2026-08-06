// Yashigani 4.0 admin shell — Capability Policy module (Governance group).
//
// YSG-RISK-163: this view existed in the OLD static/js/capability-policy.js
// (RBAC-scoped browser Permissions-Policy admin panel, 3.0) with a full
// working backend (routes/capability_policy.py), but was never ported to the
// ui4 admin SPA rebuild -- no module, no nav entry, unreachable from the
// admin shell. This is the ui4 port, following the policies-opa.js sibling
// module's registration pattern (module-registry.js contract).
//
// Endpoints (routes/capability_policy.py, all AdminSession, no step-up --
// mirrors /admin/rbac):
//   GET/PUT   /admin/api/capability-policy                    default org (all 5 caps)
//   GET/PUT/DELETE /admin/api/capability-policy/orgs/{org_id} addressable org
//   GET/PUT/DELETE /admin/api/capability-policy/groups/{id}   partial override
//   GET/PUT/DELETE /admin/api/capability-policy/users/{id}    partial override
//   GET       /admin/api/capability-policy/effective?user=... resolved preview
//
// Scope precedence (highest -> lowest): user override > group override >
// org policy > immutable BASELINE (self x5).
//
// SAFE-RENDER: capability names/values are our own CAPABILITY_NAMES enum
// (server-validated); user-entered origins are rendered via Lit text-binding
// (textContent-safe), never innerHTML.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const CAP_NAMES = ['camera', 'microphone', 'geolocation', 'display-capture', 'fullscreen'];
const CAP_LABELS = {
  camera: 'Camera',
  microphone: 'Microphone',
  geolocation: 'Geolocation',
  'display-capture': 'Display Capture',
  fullscreen: 'Fullscreen',
};
const CAP_MAX_ORIGINS = 10;

// Exported (in addition to being used internally below) so a standalone
// Node test can import and exercise the real validation logic directly —
// see src/tests/regression/v4.1.2/test_find_b_f_capability_policy_origin_validation.py
// (FIND-B-F, 2026-08-04).
export function isValidOrigin(s) {
  s = (s || '').trim();
  if (!s || s.indexOf('*') !== -1 || s.indexOf('https://') !== 0) return false;
  try {
    const url = new URL(s);
    if (url.protocol !== 'https:') return false;
    if (url.pathname !== '/') return false;
    if (url.search || url.hash || url.username || url.password) return false;
    return true;
  } catch {
    return false;
  }
}

export function normaliseOrigin(s) {
  s = (s || '').trim();
  try {
    const url = new URL(s);
    return `${url.protocol}//${url.host}`;
  } catch {
    return s;
  }
}

export class YsAdminCapabilityPolicy extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _scopeType: { state: true },     // 'org' | 'group' | 'user'
    _scopeId: { state: true },
    _groups: { state: true },
    _policy: { state: true },        // {cap: {value, allow_list}}
    _rows: { state: true },          // draft edit state per cap: {value, origins:[], input:''}
    _result: { state: true },        // {ok, message} | null
    _effUser: { state: true },
    _effResult: { state: true },     // {ok, message, effective} | null
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._scopeType = 'org';
    this._scopeId = '';
    this._groups = [];
    this._policy = {};
    this._rows = {};
    this._result = null;
    this._effUser = '';
    this._effResult = null;
    // FIND-B-E (v4.1.2 retest, lost-update race): monotonic token bumped at
    // the START of every _fetchScope() call. A response is only applied if
    // its token still matches _fetchSeq when the await resolves — any older,
    // still-in-flight fetch that resolves LATER (out of order) is a no-op
    // instead of clobbering whatever a newer scope-type/scope-id selection
    // already rendered.
    this._fetchSeq = 0;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const g = await this.api.get('/admin/rbac/groups');
    this._groups = (g && Array.isArray(g.groups)) ? g.groups : [];
    await this._fetchScope();
    this._loading = false;
  }

  _scopeUrl() {
    if (this._scopeType === 'org') return '/admin/api/capability-policy';
    if (this._scopeType === 'group') return `/admin/api/capability-policy/groups/${encodeURIComponent(this._scopeId)}`;
    return `/admin/api/capability-policy/users/${encodeURIComponent(this._scopeId)}`;
  }

  async _fetchScope(clearResult = true) {
    // FIND-CAPPOLICY-RACE-NOT-FIXED (2026-08-06): this reset used to run
    // UNCONDITIONALLY. _save()/_delete() set `this._result` to the
    // success/error badge and then `await` this same method to refresh the
    // row data from the server — but the `this._result = null` below ran
    // SYNCHRONOUSLY, before the `await` a few lines down ever yields to the
    // event loop. Lit batches synchronous reactive-property writes into a
    // single microtask render, so the render that actually painted only
    // ever saw the LATER value (null) — the "Saved."/"Override removed."
    // badge never appeared, not even briefly. The in-flight sequence-token
    // guard a few lines below (`seq !== this._fetchSeq`) is a SEPARATE
    // mechanism protecting `_rows`/`_policy` correctness on out-of-order
    // responses and is unaffected by this — it still fires unconditionally.
    // Callers that are refreshing data AFTER already setting `_result`
    // themselves (_save, _delete) now pass clearResult=false to preserve
    // their own badge; callers starting a fresh, user-initiated scope load
    // (_onScopeTypeChange, _onLoadScope, initial _load()) keep the default
    // `true` so a stale badge from a previous scope doesn't linger.
    if (clearResult) this._result = null;
    // FIND-B-E (v4.1.2 retest, lost-update race): capture the scope this
    // call is FOR before the await — a rapid scope-type change (e.g. org
    // -> group -> user in quick succession) previously re-read
    // this._scopeType/_scopeId AFTER the network round-trip, which could
    // (a) apply an older response using the label/branch of a NEWER,
    // unrelated scope (wrong "overrides" vs "org" key parsing), and
    // (b) let responses that resolve out of order clobber each other with
    // no ordering guarantee at all.
    const scopeType = this._scopeType;
    const scopeId = this._scopeId;
    const seq = ++this._fetchSeq;
    if (scopeType !== 'org' && !scopeId) {
      this._policy = {};
      this._rows = {};
      return;
    }
    const data = await this.api.get(this._scopeUrl());
    // In-flight guard: a newer _fetchScope() call (bumping _fetchSeq again)
    // started while this one was awaiting the network. Discard this now-
    // stale response instead of applying it.
    if (seq !== this._fetchSeq) return;
    const key = scopeType === 'org' ? 'org' : 'overrides';
    this._policy = (data && data[key]) ? data[key] : {};
    this._rows = this._buildRows(this._policy);
  }

  _buildRows(policy) {
    const partial = this._scopeType !== 'org';
    const rows = {};
    CAP_NAMES.forEach((cap) => {
      const setting = policy[cap] || null;
      rows[cap] = {
        value: setting ? setting.value : (partial ? '' : 'self'),
        origins: (setting && setting.allow_list) ? [...setting.allow_list] : [],
        input: '',
        error: '',
      };
    });
    return rows;
  }

  // ── Scope picker ──────────────────────────────────────────────────────────

  _onScopeTypeChange(e) {
    this._scopeType = e.target.value;
    this._scopeId = '';
    this._fetchScope();
  }

  _onScopeIdChange(e) {
    this._scopeId = e.target.value;
  }

  async _onLoadScope() {
    if (this._scopeType !== 'org' && !this._scopeId.trim()) {
      this._result = { ok: false, message: this._scopeType === 'group' ? 'Select a group first.' : 'Enter a user email first.' };
      return;
    }
    await this._fetchScope();
    this.requestUpdate();
  }

  // ── Row editing ───────────────────────────────────────────────────────────

  _onValueChange(cap, e) {
    this._rows = { ...this._rows, [cap]: { ...this._rows[cap], value: e.target.value } };
  }

  _onOriginInput(cap, e) {
    this._rows = { ...this._rows, [cap]: { ...this._rows[cap], input: e.target.value, error: '' } };
  }

  _addOrigin(cap) {
    const row = this._rows[cap];
    // FIND-B-F (2026-08-04): validate the RAW input first, THEN normalise.
    // The previous order (normalise, then validate the normalised value)
    // let normaliseOrigin() silently reconstruct a bare "scheme://host"
    // from ANY successfully-parsed URL before isValidOrigin() ever saw the
    // original string — so "https://example.com/some/path" parsed fine,
    // normaliseOrigin() rebuilt it as "https://example.com" (path silently
    // dropped), and THAT clean value passed isValidOrigin() with no error
    // shown at all: a path-bearing (or query/hash/credentials-bearing)
    // origin was silently accepted-with-correction instead of rejected,
    // even though isValidOrigin() itself correctly rejects a path when given
    // the raw string. Validating raw-then-normalising closes this without
    // weakening isValidOrigin() itself (wildcard rejection was already
    // correct either way — '*' survives URL parsing into the host and is
    // explicitly checked for).
    if (!isValidOrigin(row.input)) {
      this._rows = { ...this._rows, [cap]: { ...row, error: 'Must be https://hostname[:port] — no path, no wildcard.' } };
      return;
    }
    const origin = normaliseOrigin(row.input);
    if (row.origins.includes(origin)) {
      this._rows = { ...this._rows, [cap]: { ...row, error: 'Origin already in the list.' } };
      return;
    }
    if (row.origins.length >= CAP_MAX_ORIGINS) {
      this._rows = { ...this._rows, [cap]: { ...row, error: `Maximum ${CAP_MAX_ORIGINS} origins per capability.` } };
      return;
    }
    this._rows = { ...this._rows, [cap]: { ...row, origins: [...row.origins, origin], input: '', error: '' } };
  }

  _removeOrigin(cap, origin) {
    const row = this._rows[cap];
    this._rows = { ...this._rows, [cap]: { ...row, origins: row.origins.filter((o) => o !== origin) } };
  }

  // ── Save / delete ─────────────────────────────────────────────────────────

  _collectPolicy() {
    const partial = this._scopeType !== 'org';
    const policy = {};
    CAP_NAMES.forEach((cap) => {
      const row = this._rows[cap];
      if (!row) return;
      if (partial && row.value === '') return; // empty = inherit
      policy[cap] = { value: row.value, allow_list: row.value === 'allow_list' ? row.origins : [] };
    });
    return policy;
  }

  async _save() {
    const policy = this._collectPolicy();
    if (this._scopeType === 'org' && Object.keys(policy).length < CAP_NAMES.length) {
      this._result = { ok: false, message: `All ${CAP_NAMES.length} capabilities must be set for the org policy.` };
      return;
    }
    if (this._scopeType !== 'org' && Object.keys(policy).length === 0) {
      this._result = { ok: false, message: 'Set at least one capability to save an override.' };
      return;
    }
    const res = await this.api.mutate(this._scopeUrl(), { method: 'PUT', body: policy });
    if (res.ok) {
      this._result = { ok: true, message: 'Saved.' };
      this.app?.toast('Capability policy saved.', 'success');
      // FIND-CAPPOLICY-RACE-NOT-FIXED: clearResult=false — this refresh must
      // not wipe the "Saved." badge we just set (see _fetchScope() comment).
      await this._fetchScope(false);
    } else {
      this._result = { ok: false, message: res.error ? res.error.message : 'Save failed.' };
    }
  }

  async _delete() {
    const scopeLabel = this._scopeType === 'org'
      ? 'the org policy (will fall back to the immutable baseline)'
      : `the ${this._scopeType} override`;
    if (!confirm(`Delete / reset ${scopeLabel}?`)) return;
    const url = this._scopeType === 'group'
      ? `/admin/api/capability-policy/groups/${encodeURIComponent(this._scopeId)}`
      : this._scopeType === 'user'
        ? `/admin/api/capability-policy/users/${encodeURIComponent(this._scopeId)}`
        : '/admin/api/capability-policy/orgs/default';
    const res = await this.api.mutate(url, { method: 'DELETE' });
    if (res.ok) {
      this._result = { ok: true, message: 'Override removed.' };
      this.app?.toast('Capability policy override removed.', 'success');
      // FIND-CAPPOLICY-RACE-NOT-FIXED: clearResult=false — preserve the
      // "Override removed." badge through the refresh (see _fetchScope()).
      await this._fetchScope(false);
    } else {
      this._result = { ok: false, message: res.error ? res.error.message : 'Delete failed.' };
    }
  }

  // ── Effective policy preview ─────────────────────────────────────────────

  async _previewEffective() {
    const email = (this._effUser || '').trim();
    if (!email) {
      this._effResult = { ok: false, message: 'Enter a user email.' };
      return;
    }
    const data = await this.api.get(`/admin/api/capability-policy/effective?user=${encodeURIComponent(email)}`);
    if (!data) {
      this._effResult = { ok: false, message: 'Failed to load effective policy.' };
      return;
    }
    this._effResult = { ok: true, user: data.user || email, orgId: data.org_id || 'default', effective: data.effective || {} };
  }

  // ── Render ────────────────────────────────────────────────────────────────

  _renderScopePicker() {
    return html`
      <div class="ys-field">
        <label class="ys-label">Scope</label>
        <select class="ys-input" id="cap-scope-type" .value=${this._scopeType} @change=${(e) => this._onScopeTypeChange(e)}>
          <option value="org">Organisation (default)</option>
          <option value="group">Group</option>
          <option value="user">User</option>
        </select>
      </div>
      ${this._scopeType === 'group' ? html`
        <div class="ys-field">
          <label class="ys-label">Group</label>
          <select class="ys-input" id="cap-group-id" .value=${this._scopeId} @change=${(e) => this._onScopeIdChange(e)}>
            <option value="">${this._groups.length ? 'Select a group…' : 'No groups configured'}</option>
            ${this._groups.map((g) => html`<option value="${g.id}">${g.display_name || g.id} (${g.id})</option>`)}
          </select>
        </div>` : nothing}
      ${this._scopeType === 'user' ? html`
        <div class="ys-field">
          <label class="ys-label">User email</label>
          <input class="ys-input" id="cap-user-email" type="text" .value=${this._scopeId}
            @input=${(e) => this._onScopeIdChange(e)} placeholder="user@example.com">
        </div>` : nothing}
      <button class="ys-btn" id="cap-scope-load" @click=${() => this._onLoadScope()}>Load</button>
    `;
  }

  _renderRow(cap) {
    const row = this._rows[cap] || { value: '', origins: [], input: '', error: '' };
    const partial = this._scopeType !== 'org';
    return html`
      <tr>
        <td><strong>${CAP_LABELS[cap] || cap}</strong></td>
        <td>
          <select class="ys-input cap-val-sel" data-cap="${cap}" .value=${row.value} @change=${(e) => this._onValueChange(cap, e)}>
            ${partial ? html`<option value="">— inherit from parent</option>` : nothing}
            <option value="off">off (blocked everywhere)</option>
            <option value="self">self (same-origin only)</option>
            <option value="allow_list">allow-list (explicit origins)</option>
          </select>
        </td>
        <td>
          ${row.value === 'allow_list' ? html`
            <div class="cap-origins-area">
              <div class="cap-chips">
                ${row.origins.map((o) => html`
                  <span class="ys-chip">${o}
                    <button class="ys-chip-x" title="Remove origin" @click=${() => this._removeOrigin(cap, o)}>x</button>
                  </span>`)}
              </div>
              <div class="cap-origin-add">
                <input class="ys-input" type="url" placeholder="https://example.com" maxlength="253"
                  .value=${row.input} @input=${(e) => this._onOriginInput(cap, e)}>
                <button class="ys-btn ys-btn-ghost" @click=${() => this._addOrigin(cap)}>Add</button>
              </div>
              ${row.error ? html`<span class="ys-field-error">${row.error}</span>` : nothing}
            </div>` : nothing}
        </td>
      </tr>`;
  }

  _renderEditor() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Capability policy — ${this._scopeType === 'org' ? 'Organisation (default)' : `${this._scopeType}: ${this._scopeId}`}
        </div>
        <div class="ys-panel-body">
          ${this._scopeType !== 'org' ? html`<div class="ys-txt-note">Unset capabilities inherit from the org / baseline policy.</div>` : nothing}
          <table class="ys-table-plain">
            <thead><tr><th>Capability</th><th>Setting</th><th>Allowed origins (https:// only, max ${CAP_MAX_ORIGINS})</th></tr></thead>
            <tbody>${CAP_NAMES.map((cap) => this._renderRow(cap))}</tbody>
          </table>
          ${this._result ? html`<div class="${this._result.ok ? 'ys-badge-green' : 'ys-badge-red'} ys-badge">${this._result.message}</div>` : nothing}
          <div class="ys-actions-row">
            <button class="ys-btn" id="cap-pol-save" @click=${() => this._save()}>Save</button>
            <button class="ys-btn ys-btn-danger" id="cap-pol-delete-btn" @click=${() => this._delete()}>
              ${this._scopeType === 'org' ? 'Reset org to baseline' : `Delete ${this._scopeType} override`}
            </button>
          </div>
        </div>
      </div>`;
  }

  _renderEffective() {
    const r = this._effResult;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Effective policy preview</div>
        <div class="ys-panel-body">
          <div class="ys-field">
            <label class="ys-label">User email</label>
            <input class="ys-input" id="cap-eff-user" type="text" .value=${this._effUser}
              @input=${(e) => { this._effUser = e.target.value; }} placeholder="user@example.com">
            <button class="ys-btn" id="cap-eff-load" @click=${() => this._previewEffective()}>Resolve</button>
          </div>
          ${r ? (r.ok ? html`
            <div class="ys-badge-green ys-badge">Resolved for ${r.user} (org: ${r.orgId})</div>
            <table class="ys-table-plain">
              <thead><tr><th>Capability</th><th>Value</th><th>Origins</th></tr></thead>
              <tbody>
                ${CAP_NAMES.map((cap) => {
                  const s = r.effective[cap];
                  const origins = (s && s.allow_list && s.allow_list.length) ? s.allow_list.join(', ') : '—';
                  return html`<tr><td>${CAP_LABELS[cap] || cap}</td><td>${s ? s.value : '—'}</td><td>${origins}</td></tr>`;
                })}
              </tbody>
            </table>` : html`<div class="ys-badge-red ys-badge">${r.message}</div>`) : nothing}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading capability policy…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-panel">
          <div class="ys-panel-header">Scope</div>
          <div class="ys-panel-body">${this._renderScopePicker()}</div>
        </div>
        ${this._renderEditor()}
        ${this._renderEffective()}
      </div>`;
  }
}

customElements.define('ys-admin-capability-policy', YsAdminCapabilityPolicy);

registerAdminModule({
  id: 'capability-policy',
  label: 'Capability Policy',
  icon: '🔐',
  order: 5,     // sibling of Policies & OPA (order 0) in the Governance group
  group: 'governance',
  render: (ctx) => html`<ys-admin-capability-policy .api=${ctx.api} .app=${ctx.app}></ys-admin-capability-policy>`,
});
