// Yashigani 4.0 admin shell — Policies & OPA Assistant module (Governance group).
//
// Two governance surfaces on one page:
//   • Policy lifecycle (OPA Rego modules):
//       GET  /admin/policies                 → loaded modules + lifecycle status
//       GET  /admin/policies/lifecycle       → lifecycle records
//       GET  /admin/policies/bindings        → client-policy bindings
//       POST /admin/policies/lifecycle/{n}/promote   [STEP-UP]
//       POST /admin/policies/lifecycle/{n}/archive   [STEP-UP]
//       POST /admin/policies/activate        [STEP-UP]
//       DELETE /admin/policies/bind/{id}     [STEP-UP]
//   • OPA Assistant (AI-assisted RBAC drafting, NEW admin surface — GAP OA-01..04):
//       POST /admin/opa-assistant/suggest    → AI draft (RBAC JSON)
//       POST /admin/opa-assistant/apply      → push draft to OPA  [HITL + RISK-103]
//       POST /admin/opa-assistant/reject     → audit-only
//       GET  /admin/opa-assistant/schema     → RBAC document schema
//
// STEP-UP (RISK-103): promote/archive/activate/bind/unbind are StepUpAdminSession
// server-side — ctx.api.mutate transparently runs the shared TOTP modal on the
// server's step_up_required tag. NO client trust is involved.
//
// EU-AI-ACT HITL (Art.14): applying an AI-generated suggestion and promoting a
// policy are consequential governance acts. The AI only RECOMMENDS; the admin is
// the accountable human who DECIDES. We gate apply + promote behind an explicit
// "I approve this AI-assisted change" confirmation, and the act is audited.
//
// FINDING (RISK-103, server-side): /admin/opa-assistant/apply currently uses
// AdminSession (NOT require_stepup_admin_session), so server-side step-up is NOT
// enforced on AI-Rego apply — unlike policy promote/activate. Recommend wiring
// StepUpAdminSession on opa_assistant.apply. Surfaced in the UI as a warning.
//
// SAFE-RENDER: the AI suggestion (LLM output) and generated Rego are UNTRUSTED.
// They are rendered ONLY via Lit text-binding into <pre>/<textarea> (textContent
// auto-escape) — never innerHTML, never the markdown sink. XSS-inert by binding.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminPolicies extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _policies: { state: true },
    _lifecycle: { state: true },
    _bindings: { state: true },
    _desc: { state: true },
    _suggestion: { state: true },
    _suggestValid: { state: true },
    _suggestErr: { state: true },
    _busy: { state: true },
    _confirm: { state: true },     // {kind, name, run} pending HITL confirmation
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._policies = [];
    this._lifecycle = [];
    this._bindings = [];
    this._desc = '';
    this._suggestion = null;
    this._suggestValid = false;
    this._suggestErr = '';
    this._busy = false;
    this._confirm = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const [pol, life, bind] = await Promise.all([
      this.api.get('/admin/policies'),
      this.api.get('/admin/policies/lifecycle'),
      this.api.get('/admin/policies/bindings'),
    ]);
    this._policies = (pol && Array.isArray(pol.policies)) ? pol.policies : [];
    this._lifecycle = (life && Array.isArray(life.lifecycle)) ? life.lifecycle : [];
    this._bindings = (bind && Array.isArray(bind.bindings)) ? bind.bindings : [];
    this._loading = false;
  }

  // ── HITL gate ──────────────────────────────────────────────────────────────
  // The accountable-human decision point (EU AI Act Art.14). `run` is the actual
  // mutate; we never auto-enact — the admin must confirm first.
  _askConfirm(kind, name, run) { this._confirm = { kind, name, run }; }
  _cancelConfirm() { this._confirm = null; }
  async _doConfirm() {
    const c = this._confirm;
    this._confirm = null;
    if (c && typeof c.run === 'function') await c.run();
  }

  // ── Policy lifecycle (server step-up via ctx.api.mutate) ─────────────────────
  async _promote(name) {
    this._askConfirm('promote', name, async () => {
      const res = await this.api.mutate(`/admin/policies/lifecycle/${encodeURIComponent(name)}/promote`, { method: 'POST' });
      this._toastResult(res, `Policy ${name} promoted.`);
      if (res.ok) this._load();
    });
  }

  async _archive(name) {
    const res = await this.api.mutate(`/admin/policies/lifecycle/${encodeURIComponent(name)}/archive`, { method: 'POST' });
    this._toastResult(res, `Policy ${name} archived.`);
    if (res.ok) this._load();
  }

  async _unbind(id) {
    const res = await this.api.mutate(`/admin/policies/bind/${encodeURIComponent(id)}`, { method: 'DELETE' });
    this._toastResult(res, 'Binding removed.');
    if (res.ok) this._load();
  }

  // ── OPA Assistant ────────────────────────────────────────────────────────────
  async _suggest() {
    if (!this._desc || this._desc.trim().length < 10) {
      this.app && this.app.toast('Describe the access requirement (≥10 chars).', 'error');
      return;
    }
    this._busy = true;
    const res = await this.api.mutate('/admin/opa-assistant/suggest', {
      method: 'POST', body: { description: this._desc, include_current: true },
    });
    this._busy = false;
    if (res.ok && res.data) {
      this._suggestion = res.data.suggestion || null;
      this._suggestValid = !!res.data.valid;
      this._suggestErr = res.data.error || '';
    } else {
      this._suggestion = null; this._suggestValid = false;
      this._suggestErr = res.error ? res.error.message : 'Suggestion failed.';
    }
  }

  _apply() {
    if (!this._suggestion || !this._suggestValid) return;
    this._askConfirm('apply', 'AI-generated RBAC document', async () => {
      this._busy = true;
      const res = await this.api.mutate('/admin/opa-assistant/apply', {
        method: 'POST', body: { suggestion: this._suggestion, description: this._desc.slice(0, 500) },
      });
      this._busy = false;
      this._toastResult(res, 'AI suggestion applied to OPA.');
      if (res.ok) { this._suggestion = null; this._suggestValid = false; this._load(); }
    });
  }

  async _reject() {
    const res = await this.api.mutate('/admin/opa-assistant/reject', { method: 'POST', body: { reason: 'admin rejected in UI' } });
    this._toastResult(res, 'Suggestion rejected (audited).');
    if (res.ok) { this._suggestion = null; this._suggestValid = false; }
  }

  _toastResult(res, okMsg) {
    if (!this.app) return;
    if (res && res.ok) this.app.toast(okMsg, 'success');
    else this.app.toast(res && res.error ? res.error.message : 'Action failed.', 'error');
  }

  _renderConfirm() {
    const c = this._confirm;
    if (!c) return nothing;
    const verb = c.kind === 'apply' ? 'apply this AI-generated policy' : `promote ${c.name}`;
    return html`
      <div class="ys-modal-backdrop" @click=${(e) => { if (e.target === e.currentTarget) this._cancelConfirm(); }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Confirm AI-assisted change (human-in-the-loop)</div>
          <div class="ys-modal-body">
            <div class="ys-txt-note">
              EU AI Act Art.14: the assistant only recommends. By confirming you are the
              accountable human authorising this change. This decision is audited.
            </div>
            <p>You are about to <strong>${verb}</strong>.</p>
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn ys-btn-secondary" @click=${() => this._cancelConfirm()}>Cancel</button>
            <button class="ys-btn" id="hitl-confirm" @click=${() => this._doConfirm()}>I approve — proceed</button>
          </div>
        </div>
      </div>`;
  }

  _renderPolicies() {
    const cols = [
      { key: 'name', label: 'Policy', sortable: true },
      { key: 'category', label: 'Category', sortable: true },
      { key: 'package', label: 'Package' },
      { key: 'lifecycle_status', label: 'Lifecycle', sortable: true },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Loaded OPA policies (${this._policies.length})</div>
        <div class="ys-panel-body">
          <ys-table id="policies-table" .columns=${cols} .rows=${this._policies}
            emptyText="No policies loaded."></ys-table>
        </div>
      </div>`;
  }

  _renderLifecycle() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Client-policy lifecycle</div>
        <div class="ys-panel-body">
          ${this._lifecycle.length === 0
            ? html`<div class="ys-txt-note">No client policies tracked.</div>`
            : this._lifecycle.map((l) => html`
                <div class="ys-svc-card">
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${l.name}</div>
                    <div class="ys-txt-note">status: ${l.status || 'draft'}</div>
                  </div>
                  <button class="ys-btn" @click=${() => this._promote(l.name)}>Promote</button>
                  <button class="ys-btn ys-btn-ghost" @click=${() => this._archive(l.name)}>Archive</button>
                </div>`)}
        </div>
      </div>`;
  }

  _renderBindings() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Policy bindings (${this._bindings.length})</div>
        <div class="ys-panel-body">
          ${this._bindings.length === 0
            ? html`<div class="ys-txt-note">No bindings.</div>`
            : this._bindings.map((b) => html`
                <div class="ys-svc-card">
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${b.policy_name}</div>
                    <div class="ys-txt-note">${b.scope_kind}:${b.scope_id || '*'} · ${b.direction}</div>
                  </div>
                  <button class="ys-btn ys-btn-danger" @click=${() => this._unbind(b.binding_id || b.id)}>Unbind</button>
                </div>`)}
        </div>
      </div>`;
  }

  _renderAssistant() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">OPA Assistant — AI-drafted access control</div>
        <div class="ys-panel-body">
          <div class="ys-system-chrome" role="note">
            <div class="ys-system-chrome-msg">
              The assistant generates an RBAC data document only (never Rego). Review
              before applying — you are the accountable approver (EU AI Act Art.14).
            </div>
            <div class="ys-system-chrome-code">
              <span>RISK-103</span> — note: server-side step-up is not yet enforced on
              <span>opa-assistant/apply</span>; apply still requires this explicit HITL approval.
            </div>
          </div>
          <div class="ys-field">
            <label class="ys-label">Describe the access requirement</label>
            <textarea class="ys-textarea" id="oa-desc" .value=${this._desc}
              placeholder="e.g. analysts can read finance reports but not export them"
              @input=${(e) => { this._desc = e.target.value; }}></textarea>
          </div>
          <button class="ys-btn" id="oa-suggest" ?disabled=${this._busy} @click=${() => this._suggest()}>
            ${this._busy ? 'Working…' : 'Suggest'}
          </button>
          ${this._suggestErr ? html`<div class="ys-field-error">${this._suggestErr}</div>` : nothing}
          ${this._suggestion
            ? html`
              <div class="ys-panel-header">Suggested RBAC document</div>
              <!-- UNTRUSTED LLM output → Lit text-binding (textContent), never innerHTML -->
              <pre class="ys-md" id="oa-suggestion">${JSON.stringify(this._suggestion, null, 2)}</pre>
              <button class="ys-btn" id="oa-apply" ?disabled=${!this._suggestValid || this._busy}
                @click=${() => this._apply()}>Apply to OPA…</button>
              <button class="ys-btn ys-btn-ghost" id="oa-reject" @click=${() => this._reject()}>Reject</button>`
            : nothing}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading policies…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderAssistant()}
        <div class="ys-admin-2col">
          ${this._renderLifecycle()}
          ${this._renderBindings()}
        </div>
        ${this._renderPolicies()}
        ${this._renderConfirm()}
      </div>`;
  }
}

customElements.define('ys-admin-policies', YsAdminPolicies);

registerAdminModule({
  id: 'policies',
  label: 'Policies & OPA',
  icon: '⚖',
  order: 30,
  render: (ctx) => html`<ys-admin-policies .api=${ctx.api} .app=${ctx.app}></ys-admin-policies>`,
});
