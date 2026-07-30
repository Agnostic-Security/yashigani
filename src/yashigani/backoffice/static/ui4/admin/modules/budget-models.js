// Yashigani 4.0 admin shell — Budget & Model resources.
//
// Consolidates the resource-control surfaces of the Agents/NHI/Resources group:
// token budgets (org/group/individual + usage drill-down + tree), model aliases
// & allocations & local-model pulls, cloud-provider API keys, and the cloud
// LLM override break-glass. The high-value writes (model alias/pull/allocation,
// cloud-key set, cloud-override propose/approve/revoke) are StepUpAdminSession
// server-side — ctx.api.mutate() honours the step_up_required tag and the shared
// TOTP modal fires (RISK-103); the client never decides what needs step-up.
//
// Endpoints:
//   budget.py      GET/POST/DELETE /admin/budget/{org-caps,groups,individuals}
//                  GET /admin/budget/usage/{identity_id}  GET /admin/budget/tree
//   models.py      GET/POST/DELETE /admin/models[/{alias}]
//                  GET /admin/models/available  POST /admin/models/pull
//                  GET/POST/DELETE /admin/models/allocations[/{id}]
//                  GET/PUT/DELETE /admin/models/default (YSG-RISK-178 —
//                    admin-configurable default: local always works
//                    out-of-box; a cloud alias may be set as default only
//                    when its provider has a configured API key — server
//                    rejects with 400 otherwise, see _setDefault below)
//   cloud_keys.py  GET /admin/cloud-keys  PUT /admin/cloud-keys
//   cloud_override GET /admin/cloud-override/status  POST propose|approve|revoke
//
// TRUSTED-CHROME: all values are server-authored config/status shown via Lit
// textContent. No markdown sink, no innerHTML.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminBudgetModels extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _orgCaps: { state: true },
    _groupBudgets: { state: true },
    _indBudgets: { state: true },
    _tree: { state: true },
    _aliases: { state: true },
    _defaultModel: { state: true },
    _available: { state: true },
    _allocations: { state: true },
    _cloudKeys: { state: true },
    _override: { state: true },
    _usage: { state: true },       // {identity_id, usage} result of a drill-down
    _localInventory: { state: true }, // 4.0 Ollama local-model inventory
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._orgCaps = [];
    this._groupBudgets = [];
    this._indBudgets = [];
    this._tree = null;
    this._aliases = [];
    this._defaultModel = null;
    this._available = [];
    this._allocations = [];
    this._cloudKeys = [];
    this._override = null;
    this._usage = null;
    this._localInventory = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  _arr(x, key) {
    if (Array.isArray(x)) return x;
    if (x && key && Array.isArray(x[key])) return x[key];
    return [];
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [org, grp, ind, tree, aliases, defModel, avail, alloc, ckeys, ovr, localInv] = await Promise.all([
      this.api.get('/admin/budget/org-caps'),
      this.api.get('/admin/budget/groups'),
      this.api.get('/admin/budget/individuals'),
      this.api.get('/admin/budget/tree'),
      this.api.get('/admin/models'),
      this.api.get('/admin/models/default'),
      this.api.get('/admin/models/available'),
      this.api.get('/admin/models/allocations'),
      this.api.get('/admin/cloud-keys'),
      this.api.get('/admin/cloud-override/status'),
      this.api.get('/admin/budget/models/local-inventory'),
    ]);
    this._orgCaps = this._arr(org, 'org_caps');
    this._groupBudgets = this._arr(grp, 'groups');
    this._indBudgets = this._arr(ind, 'individuals');
    this._tree = tree || null;
    this._aliases = this._arr(aliases, 'aliases');
    this._defaultModel = defModel || null;
    this._available = this._arr(avail, 'models');
    this._allocations = this._arr(alloc, 'allocations');
    this._cloudKeys = (ckeys && Array.isArray(ckeys.providers)) ? ckeys.providers : [];
    this._override = ovr || null;
    this._localInventory = localInv || null;
    this._loading = false;
  }

  _toast(res, okMsg) {
    if (res && res.ok) this.app && this.app.toast(okMsg, 'success');
    else this.app && this.app.toast((res && res.error && res.error.message) || 'Action failed.', 'error');
  }

  // ── Budget mutations ───────────────────────────────────────────────────────
  async _addOrgCap(v) {
    const res = await this.api.mutate('/admin/budget/org-caps', { method: 'POST', body: {
      org_id: v.org_id, provider: v.provider, token_cap: Number(v.token_cap), period: v.period || 'monthly',
    } });
    this._toast(res, 'Org cap added.'); if (res.ok) await this._load();
  }
  async _delOrgCap(c) {
    const q = `org_id=${encodeURIComponent(c.org_id)}&provider=${encodeURIComponent(c.provider)}`;
    const res = await this.api.mutate(`/admin/budget/org-caps?${q}`, { method: 'DELETE' });
    this._toast(res, 'Org cap deleted.'); if (res.ok) await this._load();
  }
  async _addGroupBudget(v) {
    const res = await this.api.mutate('/admin/budget/groups', { method: 'POST', body: {
      group_id: v.group_id, provider: v.provider || '*', token_budget: Number(v.token_budget), period: v.period || 'monthly',
    } });
    this._toast(res, 'Group budget added.'); if (res.ok) await this._load();
  }
  async _delGroupBudget(b) {
    const q = `group_id=${encodeURIComponent(b.group_id)}&provider=${encodeURIComponent(b.provider)}&period=${encodeURIComponent(b.period || 'monthly')}`;
    const res = await this.api.mutate(`/admin/budget/groups?${q}`, { method: 'DELETE' });
    this._toast(res, 'Group budget deleted.'); if (res.ok) await this._load();
  }
  async _addIndBudget(v) {
    const res = await this.api.mutate('/admin/budget/individuals', { method: 'POST', body: {
      identity_id: v.identity_id, provider: v.provider || '*', token_budget: Number(v.token_budget), period: v.period || 'monthly',
    } });
    this._toast(res, 'Individual budget added.'); if (res.ok) await this._load();
  }
  async _delIndBudget(b) {
    const q = `identity_id=${encodeURIComponent(b.identity_id)}&provider=${encodeURIComponent(b.provider)}&period=${encodeURIComponent(b.period || 'monthly')}`;
    const res = await this.api.mutate(`/admin/budget/individuals?${q}`, { method: 'DELETE' });
    this._toast(res, 'Individual budget deleted.'); if (res.ok) await this._load();
  }
  async _lookupUsage(v) {
    const id = (v.identity_id || '').trim();
    if (!id) return;
    const data = await this.api.get(`/admin/budget/usage/${encodeURIComponent(id)}`);
    this._usage = data || { identity_id: id, usage: null };
  }

  // ── Model mutations ────────────────────────────────────────────────────────
  async _addAlias(v) {
    const res = await this.api.mutate('/admin/models', { method: 'POST', body: {
      alias: v.alias, provider: v.provider, model: v.model,
    } });
    this._toast(res, 'Alias created.'); if (res.ok) await this._load();
  }
  async _delAlias(a) {
    const res = await this.api.mutate(`/admin/models/${encodeURIComponent(a.alias)}`, { method: 'DELETE' });
    this._toast(res, 'Alias deleted.'); if (res.ok) await this._load();
  }
  async _setDefault(a) {
    // YSG-RISK-178: server rejects (400 cloud_default_requires_api_key) a
    // cloud alias with no configured API key — the toast surfaces that
    // message verbatim so the admin knows to configure the key first.
    const res = await this.api.mutate('/admin/models/default', { method: 'PUT', body: { alias: a.alias } });
    this._toast(res, `Default model set to ${a.alias}.`); if (res.ok) await this._load();
  }
  async _clearDefault() {
    const res = await this.api.mutate('/admin/models/default', { method: 'DELETE' });
    this._toast(res, 'Default reverted to the spec-chosen local model.'); if (res.ok) await this._load();
  }
  async _pullModel(v) {
    const res = await this.api.mutate('/admin/models/pull', { method: 'POST', body: { name: v.name } });
    this._toast(res, 'Model pull started.'); if (res.ok) await this._load();
  }
  async _addAllocation(v) {
    const res = await this.api.mutate('/admin/models/allocations', { method: 'POST', body: {
      model_alias: v.model_alias, target_type: v.target_type, target_id: v.target_id,
    } });
    this._toast(res, 'Allocation added.'); if (res.ok) await this._load();
  }
  async _delAllocation(al) {
    const id = al.alloc_id || al.id;
    const res = await this.api.mutate(`/admin/models/allocations/${encodeURIComponent(id)}`, { method: 'DELETE' });
    this._toast(res, 'Allocation removed.'); if (res.ok) await this._load();
  }

  // ── Cloud keys / override ─────────────────────────────────────────────────
  async _setCloudKey(v) {
    const res = await this.api.mutate('/admin/cloud-keys', { method: 'PUT', body: {
      provider: v.provider, api_key: v.api_key,
    } });
    this._toast(res, 'Cloud key stored.'); if (res.ok) await this._load();
  }
  async _proposeOverride(v) {
    const res = await this.api.mutate('/admin/cloud-override/propose', { method: 'POST', body: {
      provider: v.provider, model: v.model, justification: v.justification, ttl_hours: Number(v.ttl_hours || 4),
    } });
    this._toast(res, 'Override proposed.'); if (res.ok) await this._load();
  }
  async _approveOverride() {
    const res = await this.api.mutate('/admin/cloud-override/approve', { method: 'POST' });
    this._toast(res, 'Override approved.'); if (res.ok) await this._load();
  }
  async _revokeOverride() {
    const res = await this.api.mutate('/admin/cloud-override/revoke', { method: 'POST' });
    this._toast(res, 'Override revoked.'); if (res.ok) await this._load();
  }

  // ── Render helpers ─────────────────────────────────────────────────────────
  _table(cols, rows, emptyText, actions) {
    return html`
      <table class="ys-table">
        <thead><tr>${cols.map((c) => html`<th>${c.label}</th>`)}${actions ? html`<th>Actions</th>` : nothing}</tr></thead>
        <tbody>
          ${rows.length === 0
            ? html`<tr><td class="ys-table-empty" colspan=${cols.length + (actions ? 1 : 0)}>${emptyText}</td></tr>`
            : rows.map((r) => html`
                <tr>
                  ${cols.map((c) => html`<td>${c.get ? c.get(r) : (r[c.key] == null ? '—' : String(r[c.key]))}</td>`)}
                  ${actions ? html`<td>${actions(r)}</td>` : nothing}
                </tr>`)}
        </tbody>
      </table>`;
  }

  _renderBudget() {
    const periodField = { name: 'period', label: 'Period', type: 'select',
      options: [{ value: 'monthly', label: 'monthly' }, { value: 'weekly', label: 'weekly' }, { value: 'daily', label: 'daily' }] };
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Token budgets</div>
        <div class="ys-panel-body">
          <label class="ys-label">Organisation caps</label>
          ${this._table(
            [{ key: 'org_id', label: 'Org' }, { key: 'provider', label: 'Provider' }, { key: 'token_cap', label: 'Cap' }, { key: 'period', label: 'Period' }, { key: 'used', label: 'Used' }],
            this._orgCaps, 'No org caps.',
            (c) => html`<button class="ys-btn ys-btn-danger" data-act="del-orgcap" @click=${() => this._delOrgCap(c)}>Delete</button>`,
          )}
          <ys-form .fields=${[
              { name: 'org_id', label: 'Org ID', required: true },
              { name: 'provider', label: 'Provider', required: true, placeholder: 'openai' },
              { name: 'token_cap', label: 'Token cap', type: 'number', required: true },
              periodField,
            ]} submitLabel="Add org cap" @ys-submit=${(e) => this._addOrgCap(e.detail)}></ys-form>

          <label class="ys-label">Group budgets</label>
          ${this._table(
            [{ key: 'group_id', label: 'Group' }, { key: 'provider', label: 'Provider' }, { key: 'token_budget', label: 'Budget' }, { key: 'period', label: 'Period' }],
            this._groupBudgets, 'No group budgets.',
            (b) => html`<button class="ys-btn ys-btn-danger" data-act="del-grp" @click=${() => this._delGroupBudget(b)}>Delete</button>`,
          )}
          <ys-form .fields=${[
              { name: 'group_id', label: 'Group ID', required: true },
              { name: 'provider', label: 'Provider', placeholder: '*' },
              { name: 'token_budget', label: 'Token budget', type: 'number', required: true },
              periodField,
            ]} submitLabel="Add group budget" @ys-submit=${(e) => this._addGroupBudget(e.detail)}></ys-form>

          <label class="ys-label">Individual budgets</label>
          ${this._table(
            [{ key: 'identity_id', label: 'Identity' }, { key: 'provider', label: 'Provider' }, { key: 'token_budget', label: 'Budget' }, { key: 'period', label: 'Period' }],
            this._indBudgets, 'No individual budgets.',
            (b) => html`<button class="ys-btn ys-btn-danger" data-act="del-ind" @click=${() => this._delIndBudget(b)}>Delete</button>`,
          )}
          <ys-form .fields=${[
              { name: 'identity_id', label: 'Identity ID', required: true },
              { name: 'provider', label: 'Provider', placeholder: '*' },
              { name: 'token_budget', label: 'Token budget', type: 'number', required: true },
              periodField,
            ]} submitLabel="Add individual budget" @ys-submit=${(e) => this._addIndBudget(e.detail)}></ys-form>

          <label class="ys-label">Per-identity usage drill-down</label>
          <ys-form .fields=${[{ name: 'identity_id', label: 'Identity ID', required: true }]}
                   submitLabel="Look up usage" @ys-submit=${(e) => this._lookupUsage(e.detail)}></ys-form>
          ${this._usage ? html`<div class="ys-txt-note">
              Usage for ${this._usage.identity_id} (${this._usage.period || 'monthly'}):
              ${this._usage.usage == null ? 'no data' : JSON.stringify(this._usage.usage)}
            </div>` : nothing}

          <label class="ys-label">Budget tree</label>
          ${this._tree && Array.isArray(this._tree.tree) && this._tree.tree.length
            ? this._table([{ key: 'name', label: 'Node' }, { key: 'type', label: 'Type' }, { key: 'budget', label: 'Budget' }, { key: 'used', label: 'Used' }], this._tree.tree, 'Empty tree.', null)
            : html`<div class="ys-txt-note">${(this._tree && this._tree.message) || 'No budget tree data.'}</div>`}
        </div>
      </div>`;
  }

  _renderModels() {
    const availRows = this._available.map((m) => (typeof m === 'string' ? { name: m } : m));
    const dm = this._defaultModel || {};
    // YSG-RISK-178: no admin default configured (dm.alias == null) means the
    // gateway is using its spec-chosen LOCAL model (OLLAMA_MODEL, auto-picked
    // from the host's GPU/VRAM at install time) — the out-of-box behaviour.
    const defaultNote = dm.alias
      ? html`Default model: <strong>${dm.alias}</strong> (${dm.provider || '—'}/${dm.model || '—'})
          ${dm.usable === false ? html` <span class="ys-badge ys-badge-amber">unusable — no API key configured, falling back to local</span>` : nothing}`
      : html`Default model: <strong>spec-chosen local model</strong> (no admin override configured — auto-selected from this host's GPU/VRAM at install time)`;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Model aliases &amp; allocations</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note ys-txt-note--mb">
            ${defaultNote}
            ${dm.alias ? html` &nbsp;<button class="ys-btn ys-btn-danger" data-act="clear-default" @click=${() => this._clearDefault()}>Clear default</button>` : nothing}
          </div>
          <label class="ys-label">Aliases</label>
          ${this._table(
            [
              { key: 'alias', label: 'Alias', get: (a) => (dm.alias === a.alias ? html`${a.alias} <span class="ys-badge ys-badge-blue">default</span>` : a.alias) },
              { key: 'provider', label: 'Provider' }, { key: 'model', label: 'Model' },
            ],
            this._aliases, 'No aliases.',
            (a) => html`
              <button class="ys-btn" data-act="set-default" ?disabled=${dm.alias === a.alias} @click=${() => this._setDefault(a)}>Set as default</button>
              <button class="ys-btn ys-btn-danger" data-act="del-alias" @click=${() => this._delAlias(a)}>Delete</button>`,
          )}
          <ys-form .fields=${[
              { name: 'alias', label: 'Alias', required: true },
              { name: 'provider', label: 'Provider', required: true },
              { name: 'model', label: 'Model', required: true },
            ]} submitLabel="Create alias" @ys-submit=${(e) => this._addAlias(e.detail)}></ys-form>

          <label class="ys-label">Available local models</label>
          ${this._table([{ key: 'name', label: 'Model', get: (r) => r.name || r.model || r.alias || '—' }], availRows, 'No local models.', null)}
          <ys-form .fields=${[{ name: 'name', label: 'Pull model (Ollama name)', required: true, placeholder: 'qwen2.5:3b' }]}
                   submitLabel="Pull model" @ys-submit=${(e) => this._pullModel(e.detail)}></ys-form>

          <label class="ys-label">Allocations</label>
          ${this._table(
            [{ key: 'model_alias', label: 'Alias' }, { key: 'target_type', label: 'Target type' }, { key: 'target_id', label: 'Target' }],
            this._allocations, 'No allocations.',
            (al) => html`<button class="ys-btn ys-btn-danger" data-act="del-alloc" @click=${() => this._delAllocation(al)}>Remove</button>`,
          )}
          <ys-form .fields=${[
              { name: 'model_alias', label: 'Model alias', required: true },
              { name: 'target_type', label: 'Target type', type: 'select',
                options: [{ value: 'user', label: 'user' }, { value: 'group', label: 'group' }, { value: 'org', label: 'org' }] },
              { name: 'target_id', label: 'Target ID', required: true },
            ]} submitLabel="Add allocation" @ys-submit=${(e) => this._addAllocation(e.detail)}></ys-form>
        </div>
      </div>`;
  }

  _renderCloud() {
    const ovr = this._override || {};
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Cloud provider keys &amp; override</div>
        <div class="ys-panel-body">
          <label class="ys-label">Cloud API keys (KMS-stored; value never shown)</label>
          ${this._table(
            [{ key: 'provider', label: 'Provider' }, { key: 'configured', label: 'Configured', get: (r) => (r.configured ? 'yes' : 'no') }],
            this._cloudKeys, 'No providers.', null,
          )}
          <ys-form .fields=${[
              { name: 'provider', label: 'Provider', type: 'select',
                options: [{ value: 'openai', label: 'openai' }, { value: 'anthropic', label: 'anthropic' }] },
              { name: 'api_key', label: 'API key', type: 'password', required: true },
            ]} submitLabel="Store key (step-up)" @ys-submit=${(e) => this._setCloudKey(e.detail)}></ys-form>

          <label class="ys-label">Cloud LLM override (break-glass)</label>
          <div class="ys-txt-note">Status: ${ovr.status || ovr.state || (ovr.active ? 'active' : 'inactive') || '—'}${ovr.provider ? ` · ${ovr.provider}/${ovr.model || ''}` : ''}</div>
          <ys-form .fields=${[
              { name: 'provider', label: 'Provider', required: true },
              { name: 'model', label: 'Model', required: true },
              { name: 'justification', label: 'Justification (ticket / contract)', type: 'textarea', required: true },
              { name: 'ttl_hours', label: 'TTL hours (1-72)', type: 'number', placeholder: '4' },
            ]} submitLabel="Propose override (step-up)" @ys-submit=${(e) => this._proposeOverride(e.detail)}></ys-form>
          <div class="ys-field">
            <button class="ys-btn" data-act="approve-ovr" @click=${() => this._approveOverride()}>Approve override (step-up)</button>
            <button class="ys-btn ys-btn-danger" data-act="revoke-ovr" @click=${() => this._revokeOverride()}>Revoke override (step-up)</button>
          </div>
        </div>
      </div>`;
  }

  // ── Local Ollama inventory ─────────────────────────────────────────────────

  _fitsBadge(fits) {
    if (fits === true)  return html`<span class="ys-badge ys-badge-blue">fits GPU</span>`;
    if (fits === false) return html`<span class="ys-badge ys-badge-amber">too large</span>`;
    return html`<span class="ys-badge">VRAM unknown</span>`;
  }

  _renderLocalInventory() {
    const inv = this._localInventory;
    if (!inv) {
      return html`
        <div class="ys-panel ys-panel--mt">
          <div class="ys-panel-header">Local Ollama model inventory</div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">Inventory unavailable — Ollama may not be running.</div>
          </div>
        </div>`;
    }

    const gpus = Array.isArray(inv.gpus) ? inv.gpus : [];
    const models = Array.isArray(inv.models) ? inv.models : [];
    const totalVram = inv.total_vram_mib;
    const detection = inv.vram_detection || 'unavailable';

    return html`
      <div class="ys-panel ys-panel--mt">
        <div class="ys-panel-header">Local Ollama model inventory (${models.length})</div>
        <div class="ys-panel-body">

          <!-- GPU summary -->
          <div class="ys-txt-note ys-txt-note--mb">
            <strong>GPU(s):</strong>
            ${gpus.length === 0
              ? 'none detected'
              : gpus.map((g) => html`
                  ${g.name}
                  ${g.vram_mib != null
                    ? html` — <strong>${g.vram_mib} MiB</strong>`
                    : html` — VRAM unknown`}
                  <span class="ys-txt-muted"> (GPU ${g.index})</span>
                  &ensp;`)}
            ${totalVram != null
              ? html`&nbsp;· total <strong>${totalVram} MiB</strong>`
              : nothing}
            <span class="ys-txt-note ys-txt-sm"> &nbsp;(detected via ${detection})</span>
          </div>

          <!-- Model table -->
          ${models.length === 0
            ? html`<div class="ys-txt-note">No models installed in Ollama yet.
                Use "Pull model" above or <code>ollama pull &lt;name&gt;</code>.</div>`
            : html`<table class="ys-table">
                <thead>
                  <tr>
                    <th>Model</th><th>Family</th><th>Params</th>
                    <th>Quant</th><th>Size (GiB)</th><th>Est. VRAM (MiB)</th><th>GPU fit</th>
                  </tr>
                </thead>
                <tbody>
                  ${models.map((m) => html`
                    <tr>
                      <td><strong>${m.name}</strong></td>
                      <td>${m.family || '—'}</td>
                      <td>${m.parameter_size || '—'}</td>
                      <td>${m.quantization || '—'}</td>
                      <td>${m.size_gib != null ? m.size_gib : '—'}</td>
                      <td>${m.vram_estimated_mib != null ? m.vram_estimated_mib : '—'}</td>
                      <td>${this._fitsBadge(m.fits_gpu)}</td>
                    </tr>`)}
                </tbody>
              </table>`}

          <div class="ys-txt-note ys-txt-sm ys-txt-note--mt-sm">
            ${inv.note || ''}
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading budgets &amp; models…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderBudget()}
        ${this._renderModels()}
        ${this._renderLocalInventory()}
        ${this._renderCloud()}
      </div>`;
  }
}

customElements.define('ys-admin-budget-models', YsAdminBudgetModels);

registerAdminModule({
  id: 'budget-models',
  label: 'Budget & Models',
  icon: '⛁',
  order: 50,
  group: 'agents',
  render: (ctx) => html`<ys-admin-budget-models .api=${ctx.api} .app=${ctx.app}></ys-admin-budget-models>`,
});
