// Yashigani 4.0 admin shell — Agent Policy Templates module (v4.1 Phase B).
//
// Design: AgnosticSecurity/Products/Yashigani/agent-admin-policy-templates-design-20260708.md
//
// SCOPE: admin-selectable POLICY TEMPLATES for bundled agents (openclaw, langflow,
// letta) and onboarded MCP instances. NOT an extension of agents.js — that module
// is the service-agent registry CRUD; this module is a JOIN across three stores
// (registry + envelopes + grants + applications) and deserves its own read model
// (design §5.1 / Captain Q-C3).
//
// Endpoints (routes/agent_policies.py):
//   GET  /admin/agent-policies/templates              list shipped templates
//   GET  /admin/agent-policies/status                 join view (all agents + policy state)
//   POST /admin/agent-policies/{tenant}/{system}/apply   apply template (StepUp required)
//   POST /admin/agent-policies/{tenant}/{system}/adjust  re-apply with overrides (StepUp)
//   DELETE /admin/agent-policies/{tenant}/{system}/grant  revoke grant (StepUp required)
//
// SECURITY (B4 — stored-XSS fix, Laura F4, HIGH):
//
//   Flow names and graph labels from langflow are UNTRUSTED external data.
//   They MUST be rendered using Lit's html`` template tag, which auto-escapes
//   interpolated expressions via textContent semantics — NEVER via innerHTML,
//   dangerouslySetInnerHTML, or any unsanitised DOM sink.
//
//   This module uses ZERO innerHTML assignments on discovered-flow data.
//   Every agent name, flow name, SPIFFE, template ID, residual text, and
//   prefix label is interpolated as a Lit text node (textContent-safe, XSS-safe).
//
//   Mutation-XSS and attribute-injection contexts are avoided by:
//   - Never placing untrusted strings in attribute positions (href, src, etc.)
//   - Always using Lit's html`` tagged template (auto-escapes text content)
//   - Residual texts from the server come from code-versioned YAML (trusted
//     author-supplied data), but are still rendered via textContent for
//     defence-in-depth (no eval of residual text, no innerHTML).
//
// B5 — HONEST RESIDUALS:
//   Every agent row permanently shows:
//   (a) Union-grant kill-switch degradation notice (Nico Q-N1):
//       "Revoking this agent's grant kills ITS ingress; sibling agents holding
//       the same prefix keep the forwarder route active. Kill switch = grant
//       absence in OPA data."
//   (b) graph_hash is drift-detection only (Nico Q-N3):
//       "graph_hash is drift-detection metadata only — NOT attestation."
//   (c) identity_basis: "ringfence-position" — displayed per row.
//   Rows with Mode-B entries render the residual banner PERMANENTLY, not only
//   at apply time.
//
// MODE-B CONNECT: Track 2 ONLY — button / affordance is ABSENT in Track 1.
//   Any template with connect entries shows a disabled badge. The /apply route
//   returns 422 for Mode-B requests so no double-gating needed in JS, but we
//   do NOT render an "Enable Slack" button at all — the Track 2 disabled state
//   is the only rendering.
//
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

// ─────────────────────────────────────────────────────────────────────────────
// <ys-admin-agent-policies>  LitElement
// ─────────────────────────────────────────────────────────────────────────────

class YsAdminAgentPolicies extends LitElement {
  static properties = {
    api:           { attribute: false },
    app:           { attribute: false },
    _loading:      { state: true },
    _templates:    { state: true },   // [{template_id, applies_to, egress, disclosure}]
    _status:       { state: true },   // [{system_id, tenant_id, kind, spiffe_id, ...}]
    _applyDialog:  { state: true },   // null | {system_id, tenant_id, templates:[]}
    _applying:     { state: true },   // bool
    _actionResult: { state: true },   // null | {ok, message}
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._templates = [];
    this._status = [];
    this._applyDialog = null;
    this._applying = false;
    this._actionResult = null;
  }

  createRenderRoot() {
    return this;   // light DOM — shares the admin shell's CSS
  }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    try {
      const [templates, status] = await Promise.all([
        this.api.get('/admin/agent-policies/templates'),
        this.api.get('/admin/agent-policies/status'),
      ]);
      this._templates = Array.isArray(templates) ? templates : [];
      this._status = Array.isArray(status) ? status : [];
    } catch (e) {
      this.app?.toast('Failed to load agent policy data: ' + e.message, 'error');
    } finally {
      this._loading = false;
    }
  }

  // ── Apply template ────────────────────────────────────────────────────────

  _openApplyDialog(row) {
    // Filter templates compatible with this agent's system_id
    const compatTemplates = this._templates.filter((t) =>
      t.applies_to === row.system_id ||
      (t.applies_to === 'langflow-created' && String(row.system_id).startsWith('langflow-nhi-'))
    );
    this._applyDialog = {
      system_id: row.system_id,
      tenant_id: row.tenant_id,
      templates: compatTemplates,
      selected_template_id: compatTemplates[0]?.template_id || '',
    };
    this._actionResult = null;
  }

  _closeApplyDialog() {
    this._applyDialog = null;
    this._actionResult = null;
  }

  async _applyTemplate() {
    if (!this._applyDialog || !this._applyDialog.selected_template_id) return;
    this._applying = true;
    this._actionResult = null;
    try {
      const { tenant_id, system_id, selected_template_id } = this._applyDialog;
      const result = await this.api.mutate(
        'POST',
        `/admin/agent-policies/${encodeURIComponent(tenant_id)}/${encodeURIComponent(system_id)}/apply`,
        { template_id: selected_template_id, overrides: {}, acknowledgements: [] },
      );
      this._actionResult = {
        ok: true,
        message: `Template applied. Granted prefixes: ${(result.granted_prefixes || []).join(', ')}`,
      };
      await this._load();   // refresh status
    } catch (e) {
      this._actionResult = { ok: false, message: e.message || 'Apply failed' };
    } finally {
      this._applying = false;
    }
  }

  async _revokeGrant(row) {
    if (!confirm(
      `Revoke egress grant for ${row.system_id}?\n\n` +
      'Grant absence in OPA data is the kill switch — egress will be denied until a template is re-applied.'
    )) return;
    try {
      await this.api.mutate(
        'DELETE',
        `/admin/agent-policies/${encodeURIComponent(row.tenant_id)}/${encodeURIComponent(row.system_id)}/grant`,
        null,
      );
      this.app?.toast(`Grant revoked for ${row.system_id}`, 'success');
      await this._load();
    } catch (e) {
      this.app?.toast('Revoke failed: ' + e.message, 'error');
    }
  }

  // ── Render helpers ────────────────────────────────────────────────────────

  // B4 (XSS): All _render* helpers use Lit html`` tagged template exclusively.
  // Untrusted values (flow names, SPIFFE IDs, system IDs from server) are
  // interpolated as text nodes — Lit auto-escapes them (textContent-safe).
  // ZERO innerHTML / dangerouslySetInnerHTML / manual DOM manipulation.

  _renderPrefixBadge(prefix, mode) {
    // mode: 'reverse_proxy' → 'inspected' badge; 'connect' → 'host-only (Track 2)' badge
    const label = mode === 'connect' ? 'host-only (Track 2)' : 'inspected';
    const cls = mode === 'connect' ? 'badge-warning' : 'badge-info';
    // textContent-safe: prefix and label are server-sent strings
    return html`<span class="${cls} badge">${prefix}: ${label}</span> `;
  }

  _renderGrantState(row) {
    const grant = row.egress_grant;
    if (!grant) {
      return html`<span class="badge-error badge">No grant — egress denied</span>`;
    }
    const prefixes = Array.isArray(grant.prefixes) ? grant.prefixes : [];
    return html`
      <span class="badge-success badge">Active</span>
      ${prefixes.map((p) => this._renderPrefixBadge(p, 'reverse_proxy'))}
      ${grant.has_connect ? html`<span class="badge-warning badge">+connect (Mode B)</span>` : nothing}
    `;
  }

  _renderResiduals(row) {
    // B5: Honest residual notices — always present, always rendered as text nodes
    const r = row.residuals || {};
    return html`
      <details class="residual-details">
        <summary class="residual-summary">Security residuals &amp; identity basis</summary>
        <div class="residual-body">
          <p class="residual-identity">
            Identity basis: <strong>${r.identity_basis || 'ringfence-position'}</strong>
          </p>
          ${r.union_grant_note ? html`
            <p class="residual-union">
              ⚠ Kill-switch note: ${r.union_grant_note}
            </p>
          ` : nothing}
          ${r.graph_hash_note ? html`
            <p class="residual-graph">
              ℹ ${r.graph_hash_note}
            </p>
          ` : nothing}
          ${r.egress_attribution_note ? html`
            <p class="residual-egress-attribution">
              ⚠ Egress attribution: ${r.egress_attribution_note}
            </p>
          ` : nothing}
        </div>
      </details>
    `;
  }

  _renderApplyDialog() {
    const d = this._applyDialog;
    if (!d) return nothing;
    // textContent-safe: system_id from server (validated slug)
    return html`
      <div class="dialog-backdrop" @click=${() => this._closeApplyDialog()}>
        <div class="dialog" @click=${(e) => e.stopPropagation()}>
          <h3>Apply Policy Template</h3>
          <p>Agent: <strong>${d.system_id}</strong></p>

          <label>
            Template:
            <select
              .value=${d.selected_template_id}
              @change=${(e) => { this._applyDialog = { ...d, selected_template_id: e.target.value }; }}
            >
              ${d.templates.map((t) => html`
                <option value="${t.template_id}">${t.template_id} — ${t.description || t.applies_to}</option>
              `)}
            </select>
          </label>

          ${d.selected_template_id ? this._renderTemplatePreview(d.selected_template_id) : nothing}

          ${this._actionResult ? html`
            <div class="${this._actionResult.ok ? 'alert-success' : 'alert-error'} alert">
              ${this._actionResult.message}
            </div>
          ` : nothing}

          <div class="dialog-actions">
            <button @click=${() => this._closeApplyDialog()}>Cancel</button>
            <button
              class="btn-primary"
              ?disabled=${this._applying || !d.selected_template_id}
              @click=${() => this._applyTemplate()}
            >
              ${this._applying ? 'Applying…' : 'Apply (step-up required)'}
            </button>
          </div>
        </div>
      </div>
    `;
  }

  _renderTemplatePreview(templateId) {
    const t = this._templates.find((x) => x.template_id === templateId);
    if (!t) return nothing;
    const hasConnectEntry = (t.egress || []).some((e) => e.mode === 'connect');
    return html`
      <div class="template-preview">
        <h4>Template: ${t.template_id}</h4>
        <ul>
          ${(t.egress || []).map((e) => html`
            <li>
              ${e.prefix}:
              ${e.mode === 'connect'
                ? html`<em>Mode B CONNECT — Track 2 only, disabled in this track</em>`
                : html`Mode A (inspected)`
              }
            </li>
          `)}
        </ul>
        ${hasConnectEntry ? html`
          <div class="alert-warning alert">
            This template contains Mode-B CONNECT entries (Track 2 only).
            They will NOT be applied in Track 1 — only Mode-A prefixes take effect.
          </div>
        ` : nothing}
        ${(t.disclosure?.residuals || []).map((res) => html`
          <div class="residual-box">
            <strong>[${res.id}]</strong> ${res.text}
          </div>
        `)}
      </div>
    `;
  }

  _renderRow(row) {
    const hasGrant = Boolean(row.egress_grant);
    const hasTemplate = Boolean(row.template_applied?.template_id);
    // textContent-safe: all values from server (strings, never HTML)
    return html`
      <tr>
        <td>
          <strong>${row.system_id}</strong>
          <br><small class="muted">${row.kind}</small>
        </td>
        <td>
          <small class="mono">${row.spiffe_id || '—'}</small>
          <br><small class="${row.svid_issued ? 'text-ok' : 'text-warn'}">
            ${row.svid_issued ? 'Leaf issued' : 'No leaf'}
          </small>
        </td>
        <td>${this._renderGrantState(row)}</td>
        <td>
          ${hasTemplate
            ? html`${row.template_applied.template_id} v${row.template_applied.version}`
            : html`<em class="muted">None — egress denied</em>`
          }
          ${hasTemplate && row.template_applied.applied_by ? html`
            <br><small class="muted">by ${row.template_applied.applied_by}</small>
          ` : nothing}
        </td>
        <td>
          ${this._renderResiduals(row)}
        </td>
        <td class="actions">
          <button
            class="btn-sm btn-secondary"
            @click=${() => this._openApplyDialog(row)}
          >Apply</button>
          ${hasGrant ? html`
            <button
              class="btn-sm btn-danger"
              @click=${() => this._revokeGrant(row)}
            >Revoke</button>
          ` : nothing}
        </td>
      </tr>
    `;
  }

  render() {
    if (this._loading) {
      return html`<div class="loading">Loading agent policy data…</div>`;
    }
    return html`
      <div class="section-header">
        <h2>Agent Policy Templates</h2>
        <button class="btn-sm btn-secondary" @click=${() => this._load()}>Refresh</button>
      </div>

      <p class="section-intro">
        Manage egress-grant policies for bundled agents (openclaw, langflow, letta)
        and onboarded MCP instances. Applying a template writes a positive egress grant
        to OPA live. Revocation is immediate: grant absence = deny.
      </p>

      <div class="notice-box">
        <strong>Mode-B CONNECT (openclaw-Slack):</strong>
        Track 2 only — not available in this release.
        See design §3.2 (gated on Laura FP-01 re-review).
      </div>

      ${this._status.length === 0
        ? html`<p class="empty-state">No agents registered yet.</p>`
        : html`
          <table class="admin-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Identity (SPIFFE)</th>
                <th>Egress grant</th>
                <th>Template applied</th>
                <th>Residuals</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${this._status.map((row) => this._renderRow(row))}
            </tbody>
          </table>
        `}

      ${this._renderApplyDialog()}
    `;
  }
}

customElements.define('ys-admin-agent-policies', YsAdminAgentPolicies);

registerAdminModule({
  id:    'agent-policies',
  label: 'Agent Policies',
  icon:  '🛡',
  order: 46,     // between agents (45) and NHI approvals (47) in the Agents group
  group: 'agents',
  render: (ctx) => html`
    <ys-admin-agent-policies
      .api=${ctx.api}
      .app=${ctx.app}
    ></ys-admin-agent-policies>
  `,
});
