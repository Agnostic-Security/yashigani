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
    // YSG-RISK-210 / FIND-B-E: lost-update race guard state (see
    // _fetchScope() below — two independently-found and complementary
    // guards against the same class of race, both kept).
    _dirty: { state: true },         // true if _rows has an unsaved edit since the last fetch/save
    _fetchInFlight: { state: true }, // true while a _fetchScope() GET is pending
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
    this._dirty = false;
    this._fetchInFlight = false;
    // FIND-B-E (v4.1.2 retest, lost-update race): monotonic token bumped at
    // the START of every _fetchScope() call. A response is only applied if
    // its token still matches _fetchSeq when the await resolves — any older,
    // still-in-flight fetch that resolves LATER (out of order) is a no-op
    // instead of clobbering whatever a newer scope-type/scope-id selection
    // already rendered. Kept alongside the _fetchInFlight guard above (which
    // normally prevents overlap at entry) as defence-in-depth, and because
    // it also protects against the DOM-mutation ordering gap described below.
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

  // YSG-RISK-210 / FIND-B-E (lost-update race, root-caused by Ava 2026-08-03
  // in test_capability_policy_ui.py::test_save_org_policy_camera_off;
  // live-confirmed two independent ways, incl. a raw DOM dispatchEvent
  // bypassing Playwright — independently re-found in the v4.1.2 retest as
  // FIND-B-E). Guards now applied, all kept together (union, not either/or):
  //   1. `_fetchInFlight` — a second overlapping call (e.g. a rapid
  //      double-click on Load, or a scope-type change firing while a prior
  //      fetch for a different scope hasn't settled) is dropped rather than
  //      letting two in-flight GETs race each other for who writes _rows last.
  //   2. `_dirty` — if the user edited a row (see _onValueChange / _addOrigin /
  //      _removeOrigin) *after* this fetch started but *before* it resolved,
  //      the edit is KEPT (never silently discarded) and the user is told via
  //      a visible `.ys-badge` instead. Callers that intend to abandon the
  //      current draft (_onScopeTypeChange on an actual change, _onLoadScope)
  //      clear `_dirty` synchronously before starting the new fetch cycle, so
  //      only edits racing THIS fetch are protected.
  //   3. Local `scopeType`/`scopeId`/`seq` capture + `_fetchSeq` monotonic
  //      token (FIND-B-E) — closes a gap the `_fetchInFlight` guard alone
  //      does NOT cover: `_onScopeTypeChange` mutates `this._scopeType` /
  //      `this._scopeId` synchronously and unconditionally (it doesn't wait
  //      on `_fetchInFlight`), so an in-flight fetch that re-read
  //      `this._scopeType` AFTER its await could apply an old response using
  //      a NEW scope's label/branch (wrong "overrides" vs "org" key
  //      parsing). Capturing locals before the `await`, and bailing if
  //      `_fetchSeq` moved on, makes stale responses a no-op regardless of
  //      how they went stale.
  // Also: this does not unconditionally null `_result` (FIND-CAPPOLICY-RACE-
  // NOT-FIXED, 2026-08-06 — `_save()`/`_delete()` set a success/error
  // `_result` then call this to refresh rows; an unconditional
  // `this._result = null` here ran SYNCHRONOUSLY before the `await` yielded,
  // so Lit's microtask-batched render only ever saw the later null and the
  // "Saved."/"Override removed." badge never painted). `clearResult`
  // defaults to `true` for fresh, user-initiated loads (_onScopeTypeChange,
  // _onLoadScope, initial _load()); `_save()`/`_delete()` pass `false` to
  // preserve the badge they just set.
  async _fetchScope(clearResult = true) {
    if (this._fetchInFlight) return;
    this._fetchInFlight = true;
    if (clearResult) this._result = null;
    const scopeType = this._scopeType;
    const scopeId = this._scopeId;
    const seq = ++this._fetchSeq;
    try {
      if (scopeType !== 'org' && !scopeId) {
        this._policy = {};
        this._rows = {};
        this._dirty = false;
        return;
      }
      const data = await this.api.get(this._scopeUrl());
      if (seq !== this._fetchSeq) return; // superseded by a newer fetch — stale response, no-op
      if (this._dirty) {
        // An edit landed while this GET was in flight. Do not clobber it —
        // keep `_rows` exactly as the user left them and say so.
        this._result = {
          ok: false,
          message: 'Scope data was refreshed from the server while you had an unsaved edit — your edit was kept. Save it, or reload the scope to discard it.',
        };
        return;
      }
      const key = scopeType === 'org' ? 'org' : 'overrides';
      this._policy = (data && data[key]) ? data[key] : {};
      this._rows = this._buildRows(this._policy);
      this._dirty = false;
    } finally {
      this._fetchInFlight = false;
    }
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
    // YSG-RISK-210: the <select>'s @change handler used to re-fetch
    // unconditionally, even when the value hadn't actually changed
    // (confirmed live: re-selecting "org" re-triggers _fetchScope() and can
    // still silently revert an in-progress edit). Guard on an actual change.
    if (e.target.value === this._scopeType) return;
    this._scopeType = e.target.value;
    this._scopeId = '';
    this._result = null;
    this._dirty = false; // starting a fresh fetch cycle for a different scope
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
    this._result = null;
    this._dirty = false; // explicit reload — starting a fresh fetch cycle
    await this._fetchScope();
    this.requestUpdate();
  }

  // ── Row editing ───────────────────────────────────────────────────────────

  _onValueChange(cap, e) {
    this._rows = { ...this._rows, [cap]: { ...this._rows[cap], value: e.target.value } };
    this._dirty = true; // YSG-RISK-210: mark unsaved-edit so an in-flight fetch can't clobber it
  }

  _onOriginInput(cap, e) {
    // Draft text only (not yet committed to the row's origins list via
    // _addOrigin) — not tracked as `_dirty`; it isn't part of what
    // _collectPolicy() persists.
    this._rows = { ...this._rows, [cap]: { ...this._rows[cap], input: e.target.value, error: '' } };
  }

  _addOrigin(cap) {
    const row = this._rows[cap];
    // YSG-RISK-211 / FIND-B-F (independently found by both v4.1.2 sessions,
    // same root cause): this used to call normaliseOrigin(row.input) BEFORE
    // validating, then validate the *normalised* value. That's backwards and
    // let both invalid shapes through:
    //   - "https://example.com/some/path" -> normaliseOrigin() rebuilds the
    //     origin from `${url.protocol}//${url.host}`, which silently DROPS
    //     the path. isValidOrigin() then ran on the already-pathless value
    //     and passed it.
    //   - "https://*.example.com" -> normaliseOrigin() round-trips the string
    //     through `new URL()`, which percent-encodes '*' to '%2A' in
    //     url.host. isValidOrigin()'s `indexOf('*')` check then ran on
    //     "https://%2A.example.com", which no longer contains a literal '*',
    //     so it passed too.
    // Live-confirmed both bypasses in a headless-Chromium eval before fixing.
    // Fix: validate the RAW trimmed input (where '*' is still literal and the
    // path is still present) and only normalise a value that already passed.
    // Server-side (capability_policy/model.py _HTTPS_ORIGIN_RE) was checked
    // and already rejects both shapes correctly — this was a client-only gap.
    const raw = (row.input || '').trim();
    if (!isValidOrigin(raw)) {
      this._rows = { ...this._rows, [cap]: { ...row, error: 'Must be https://hostname[:port] — no path, no wildcard.' } };
      return;
    }
    const origin = normaliseOrigin(raw);
    if (row.origins.includes(origin)) {
      this._rows = { ...this._rows, [cap]: { ...row, error: 'Origin already in the list.' } };
      return;
    }
    if (row.origins.length >= CAP_MAX_ORIGINS) {
      this._rows = { ...this._rows, [cap]: { ...row, error: `Maximum ${CAP_MAX_ORIGINS} origins per capability.` } };
      return;
    }
    this._rows = { ...this._rows, [cap]: { ...row, origins: [...row.origins, origin], input: '', error: '' } };
    this._dirty = true; // YSG-RISK-210
  }

  _removeOrigin(cap, origin) {
    const row = this._rows[cap];
    this._rows = { ...this._rows, [cap]: { ...row, origins: row.origins.filter((o) => o !== origin) } };
    this._dirty = true; // YSG-RISK-210
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
      // FIND-0805-003: the edit is now persisted server-side, so it's no
      // longer "dirty" -- clear it BEFORE the refresh below so _fetchScope()
      // takes the normal rebuild path (and, per YSG-RISK-210 fix, no longer
      // nulls `_result` itself, so this "Saved." badge actually paints).
      this._dirty = false;
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
      this._dirty = false; // FIND-0805-003 / YSG-RISK-210 — see _save() above
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
    // YSG-RISK-210: disable the scope-switching controls while a fetch is
    // in flight (defence-in-depth alongside the _dirty guard in
    // _fetchScope() -- this stops a second overlapping fetch from being
    // triggered via the UI in the first place; the _dirty guard is what
    // actually protects against the raw-DOM-dispatchEvent bypass Ava found,
    // since a `disabled` control still delivers synthetic events).
    return html`
      <div class="ys-field">
        <label class="ys-label">Scope</label>
        <select class="ys-input" id="cap-scope-type" .value=${this._scopeType} ?disabled=${this._fetchInFlight}
          @change=${(e) => this._onScopeTypeChange(e)}>
          <option value="org">Organisation (default)</option>
          <option value="group">Group</option>
          <option value="user">User</option>
        </select>
      </div>
      ${this._scopeType === 'group' ? html`
        <div class="ys-field">
          <label class="ys-label">Group</label>
          <select class="ys-input" id="cap-group-id" .value=${this._scopeId} ?disabled=${this._fetchInFlight}
            @change=${(e) => this._onScopeIdChange(e)}>
            <option value="">${this._groups.length ? 'Select a group…' : 'No groups configured'}</option>
            ${this._groups.map((g) => html`<option value="${g.id}">${g.display_name || g.id} (${g.id})</option>`)}
          </select>
        </div>` : nothing}
      ${this._scopeType === 'user' ? html`
        <div class="ys-field">
          <label class="ys-label">User email</label>
          <input class="ys-input" id="cap-user-email" type="text" .value=${this._scopeId} ?disabled=${this._fetchInFlight}
            @input=${(e) => this._onScopeIdChange(e)} placeholder="user@example.com">
        </div>` : nothing}
      <button class="ys-btn" id="cap-scope-load" ?disabled=${this._fetchInFlight} @click=${() => this._onLoadScope()}>Load</button>
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
