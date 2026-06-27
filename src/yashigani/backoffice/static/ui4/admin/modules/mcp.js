// Yashigani 4.0 admin shell — MCP Registry / capability-envelope re-approvals.
//
// Imported MCP servers are pinned at import behind a capability envelope (typed
// tool surface + egress posture). When an upstream MCP's tool surface drifts
// (the anti-rug-pull case), the refresh is BLOCKED and queued here for an
// operator re-approval decision. The broker keeps the MCP hard-gated
// (fail-closed) until an admin re-pins a new baseline or rejects.
//
// Endpoints (routes/envelope_reapproval.py, prefix /admin/mcp/envelopes):
//   GET  /pending                          — blocked refreshes for this tenant
//   GET  /pending/{provenance_id}          — field-level diff vs original + prior
//   POST /pending/{provenance_id}/approve  — re-pin new baseline (step-up gate)
//   POST /pending/{provenance_id}/reject   — keep blocked (step-up gate)
//
// The approve/reject routes enforce assert_privileged_mutation server-side and
// raise 401 step_up_required → the shared TOTP modal fires via ctx.api.
//
// TRUSTED-CHROME header views; the diff tool_key/detail strings are UNTRUSTED
// (attacker-influenced MCP metadata) but are still rendered via Lit textContent
// auto-escape — never a markdown/innerHTML sink — so they are inert.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const BASE = '/admin/mcp/envelopes';

function sevBadge(sev) {
  if (sev === 'high') return 'ys-badge ys-badge-red';
  if (sev === 'med') return 'ys-badge ys-badge-amber';
  return 'ys-badge ys-badge-blue';
}

export class YsAdminMcp extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _pending: { state: true },
    _diff: { state: true },     // loaded diff for the open provenance, or null
    _busy: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._pending = [];
    this._diff = null;
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
    const data = await this.api.get(`${BASE}/pending`);
    this._pending = (data && Array.isArray(data.pending)) ? data.pending : [];
    this._loading = false;
  }

  async _openDiff(row) {
    const pid = row.provenance_id;
    const data = await this.api.get(`${BASE}/pending/${encodeURIComponent(pid)}`);
    if (data) this._diff = data;
    else this.app && this.app.toast('Could not load diff.', 'error');
  }

  async _decide(pid, action) {
    this._busy = `${pid}:${action}`;
    const res = await this.api.mutate(`${BASE}/pending/${encodeURIComponent(pid)}/${action}`, { method: 'POST' });
    this._busy = '';
    if (res.ok) {
      this.app && this.app.toast(action === 'approve' ? 'Envelope re-pinned; block cleared.' : 'Mutation rejected; MCP stays blocked.', 'success');
      this._diff = null;
      await this._load();
    } else {
      this.app && this.app.toast((res.error && res.error.message) || 'Decision failed.', 'error');
    }
  }

  _renderFindings(title, findings) {
    return html`
      <div class="ys-field">
        <label class="ys-label">${title} (${findings.length})</label>
        ${findings.length === 0
          ? html`<div class="ys-txt-note">No changes.</div>`
          : html`<table class="ys-table">
              <thead><tr><th>Change</th><th>Severity</th><th>Tool</th><th>Detail</th></tr></thead>
              <tbody>
                ${findings.map((f) => html`
                  <tr>
                    <td>${f.label}</td>
                    <td><span class=${sevBadge(f.severity)}>${f.severity}</span></td>
                    <td>${f.tool_key || '—'}</td>
                    <td>${f.detail || '—'}</td>
                  </tr>`)}
              </tbody>
            </table>`}
      </div>`;
  }

  _renderDiffModal() {
    if (!this._diff) return nothing;
    const d = this._diff;
    const pid = d.provenance_id;
    return html`
      <div class="ys-modal-backdrop" @click=${(ev) => { if (ev.target === ev.currentTarget) this._diff = null; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Tool-surface drift — ${d.server_id || pid}</div>
          <div class="ys-modal-body">
            <div class="ys-txt-note">
              Triage: ${d.triage_class || '—'} ·
              Egress: ${d.egress_from} → ${d.egress_to}
              ${d.egress_change ? html` <span class="ys-badge ys-badge-red">egress changed</span>` : nothing}
            </div>
            ${this._renderFindings('Changes vs ORIGINAL baseline (anti-rug-pull anchor)', d.vs_original || [])}
            ${this._renderFindings('Changes vs prior approved', d.vs_prior || [])}
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn ys-btn-secondary" @click=${() => { this._diff = null; }}>Close</button>
            <button class="ys-btn ys-btn-danger" data-act="reject"
                    ?disabled=${this._busy.startsWith(pid)}
                    @click=${() => this._decide(pid, 'reject')}>Reject (keep blocked)</button>
            <button class="ys-btn" data-act="approve"
                    ?disabled=${this._busy.startsWith(pid)}
                    @click=${() => this._decide(pid, 'approve')}>Approve &amp; re-pin</button>
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading MCP re-approval queue…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-panel">
          <div class="ys-panel-header">
            MCP tool-surface re-approvals (${this._pending.length})
            ${this._pending.length ? html`<span class="ys-badge ys-badge-amber">action required</span>` : nothing}
          </div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">
              Imported MCP servers are pinned to an approved capability envelope. A drifted
              tool surface is blocked (fail-closed) until you re-pin a new baseline or reject.
            </div>
            ${this._pending.length === 0
              ? html`<div class="ys-txt-note">Queue empty — no blocked MCP refreshes.</div>`
              : html`<table class="ys-table">
                  <thead><tr><th>Server</th><th>Provenance</th><th>Triage</th><th>Action</th></tr></thead>
                  <tbody>
                    ${this._pending.map((r) => html`
                      <tr>
                        <td>${r.server_id || '—'}</td>
                        <td>${r.provenance_id}</td>
                        <td>${r.triage_class || '—'}</td>
                        <td><button class="ys-btn" data-act="view" @click=${() => this._openDiff(r)}>Review diff</button></td>
                      </tr>`)}
                  </tbody>
                </table>`}
          </div>
        </div>
        ${this._renderDiffModal()}
      </div>`;
  }
}

customElements.define('ys-admin-mcp', YsAdminMcp);

registerAdminModule({
  id: 'mcp',
  label: 'MCP Registry',
  icon: '⧉',
  order: 26,
  render: (ctx) => html`<ys-admin-mcp .api=${ctx.api} .app=${ctx.app}></ys-admin-mcp>`,
});
