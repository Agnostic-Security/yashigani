// Yashigani 4.0 admin shell — MCP Registry.
//
// Two panels:
//   1. Registered MCP Servers — active approved envelopes (GET /admin/mcp/servers/).
//      Shows each server, its tool count, effect classes, and egress posture.
//      The cloud-9 demo MCP appears here after populate-demo.py seeds the import.
//
//   2. Tool-surface re-approvals — blocked refreshes pending operator decision
//      (GET /admin/mcp/envelopes/pending).  When an upstream MCP's tool surface
//      drifts (the anti-rug-pull case), the refresh is BLOCKED until an operator
//      re-pins a new baseline or rejects.
//
// Import ceremony (admin action — step-up gated):
//   POST /admin/mcp/servers/import  →  fetch tools/list + mint v1 envelope.
//   Used by the "Import MCP Server" form (admin must provide server_id + URL).
//   In demo mode populate-demo.py calls this API directly at deploy time.
//
// Endpoints (envelope re-approval):
//   GET  /admin/mcp/envelopes/pending                    — blocked refreshes
//   GET  /admin/mcp/envelopes/pending/{provenance_id}   — field-level diff
//   POST /admin/mcp/envelopes/pending/{prov}/approve    — step-up re-approve
//   POST /admin/mcp/envelopes/pending/{prov}/reject     — keep blocked
//
// TRUSTED-CHROME header views; tool_key/detail strings are UNTRUSTED
// (attacker-influenced MCP metadata) but rendered via Lit textContent
// auto-escape — never a markdown/innerHTML sink.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const SERVERS_BASE = '/admin/mcp/servers';
const ENVELOPES_BASE = '/admin/mcp/envelopes';

function sevBadge(sev) {
  if (sev === 'high') return 'ys-badge ys-badge-red';
  if (sev === 'med') return 'ys-badge ys-badge-amber';
  return 'ys-badge ys-badge-blue';
}

function postureBadge(posture) {
  if (!posture || posture === 'NONE') return 'ys-badge ys-badge-blue';
  if (posture === 'OPEN') return 'ys-badge ys-badge-red';
  return 'ys-badge ys-badge-amber';
}

export class YsAdminMcp extends LitElement {
  static properties = {
    api:       { attribute: false },
    app:       { attribute: false },
    _loading:  { state: true },
    _servers:  { state: true },   // active registered servers
    _pending:  { state: true },   // pending re-approval queue
    _diff:     { state: true },   // loaded diff for open provenance, or null
    _busy:     { state: true },
    _showImport: { state: true }, // show the import form
    _importing:  { state: true },
    _importError: { state: true },
    _importServerId: { state: true },
    _importUrl:      { state: true },
    _importTopology: { state: true },
    _importEgress:   { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._servers = [];
    this._pending = [];
    this._diff = null;
    this._busy = '';
    this._showImport = false;
    this._importing = false;
    this._importError = '';
    this._importServerId = '';
    this._importUrl = '';
    this._importTopology = 'ring_fenced';
    this._importEgress = 'NONE';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [svData, envData] = await Promise.all([
      this.api.get(`${SERVERS_BASE}/`),
      this.api.get(`${ENVELOPES_BASE}/pending`),
    ]);
    this._servers = (svData && Array.isArray(svData.servers)) ? svData.servers : [];
    this._pending = (envData && Array.isArray(envData.pending)) ? envData.pending : [];
    this._loading = false;
  }

  // ── Re-approval queue actions ─────────────────────────────────────────────

  async _openDiff(row) {
    const pid = row.provenance_id;
    const data = await this.api.get(`${ENVELOPES_BASE}/pending/${encodeURIComponent(pid)}`);
    if (data) this._diff = data;
    else this.app && this.app.toast('Could not load diff.', 'error');
  }

  async _decide(pid, action) {
    this._busy = `${pid}:${action}`;
    const res = await this.api.mutate(
      `${ENVELOPES_BASE}/pending/${encodeURIComponent(pid)}/${action}`,
      { method: 'POST' }
    );
    this._busy = '';
    if (res.ok) {
      this.app && this.app.toast(
        action === 'approve'
          ? 'Envelope re-pinned; block cleared.'
          : 'Mutation rejected; MCP stays blocked.',
        'success'
      );
      this._diff = null;
      await this._load();
    } else {
      this.app && this.app.toast((res.error && res.error.message) || 'Decision failed.', 'error');
    }
  }

  // ── Import ceremony ──────────────────────────────────────────────────────

  async _importServer() {
    this._importing = true;
    this._importError = '';
    const body = {
      server_id: this._importServerId.trim(),
      upstream_url: this._importUrl.trim(),
      topology: this._importTopology,
      egress_posture: this._importEgress,
    };
    const res = await this.api.mutate(`${SERVERS_BASE}/import`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    this._importing = false;
    if (res.ok) {
      this.app && this.app.toast(
        `Imported ${res.data.server_id}: ${res.data.tool_count} tool(s) enveloped.`,
        'success'
      );
      this._showImport = false;
      this._importServerId = '';
      this._importUrl = '';
      await this._load();
    } else {
      const msg = (res.error && res.error.message) || 'Import failed.';
      this._importError = msg;
      this.app && this.app.toast(msg, 'error');
    }
  }

  // ── Render helpers ────────────────────────────────────────────────────────

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

  _renderImportModal() {
    if (!this._showImport) return nothing;
    return html`
      <div class="ys-modal-backdrop" @click=${(ev) => { if (ev.target === ev.currentTarget) this._showImport = false; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Import MCP Server (step-up required)</div>
          <div class="ys-modal-body">
            <div class="ys-txt-note">
              Imports a new MCP server: fetches its tool surface, projects the capability
              envelope, and mints v1 (the approved baseline). Requires a fresh TOTP stamp.
            </div>
            <div class="ys-field">
              <label class="ys-label" for="import-sid">Server ID</label>
              <input class="ys-input" id="import-sid" type="text"
                     placeholder="cloud9-demo"
                     .value=${this._importServerId}
                     @input=${(e) => { this._importServerId = e.target.value; }} />
              <div class="ys-txt-note">Must match the agent_name in YASHIGANI_MCP_SERVERS.</div>
            </div>
            <div class="ys-field">
              <label class="ys-label" for="import-url">Upstream URL</label>
              <input class="ys-input" id="import-url" type="text"
                     placeholder="http://demo-mcp:8000"
                     .value=${this._importUrl}
                     @input=${(e) => { this._importUrl = e.target.value; }} />
              <div class="ys-txt-note">JSON-RPC endpoint the backoffice will call for tools/list.</div>
            </div>
            <div class="ys-field">
              <label class="ys-label" for="import-topo">Topology</label>
              <select class="ys-select" id="import-topo"
                      .value=${this._importTopology}
                      @change=${(e) => { this._importTopology = e.target.value; }}>
                <option value="ring_fenced">ring_fenced (compose-internal)</option>
                <option value="external_relay">external_relay (public/cloud)</option>
              </select>
            </div>
            <div class="ys-field">
              <label class="ys-label" for="import-egress">Egress Posture</label>
              <select class="ys-select" id="import-egress"
                      .value=${this._importEgress}
                      @change=${(e) => { this._importEgress = e.target.value; }}>
                <option value="NONE">NONE (no egress)</option>
                <option value="CONTROLLED">CONTROLLED (declared egress only)</option>
                <option value="OPEN">OPEN (unrestricted egress)</option>
              </select>
            </div>
            ${this._importError
              ? html`<div class="ys-txt-note ys-txt-danger">${this._importError}</div>`
              : nothing}
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn ys-btn-secondary"
                    @click=${() => { this._showImport = false; this._importError = ''; }}>
              Cancel
            </button>
            <button class="ys-btn"
                    ?disabled=${this._importing || !this._importServerId.trim() || !this._importUrl.trim()}
                    @click=${() => this._importServer()}>
              ${this._importing ? 'Importing…' : 'Import (step-up)'}
            </button>
          </div>
        </div>
      </div>`;
  }

  _renderServerRow(s) {
    return html`
      <tr>
        <td><strong>${s.server_id}</strong></td>
        <td>${s.tool_count}</td>
        <td>
          <span class=${postureBadge(s.egress_posture)}>${s.egress_posture || 'NONE'}</span>
        </td>
        <td>${s.topology || '—'}</td>
        <td>v${s.envelope_version}</td>
        <td>${s.approved_by || '—'}</td>
      </tr>
      ${s.tools && s.tools.length > 0 ? html`
        <tr>
          <td colspan="6" class="ys-mcp-tools-cell">
            <div class="ys-txt-note ys-txt-sm">
              Tools: ${s.tools.map((t) => html`
                <span class="ys-badge ys-badge--gap">${t.tool_key}</span>
              `)}
            </div>
          </td>
        </tr>` : nothing}`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading MCP registry…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">

        <!-- Panel 1: Registered MCP Servers -->
        <div class="ys-panel">
          <div class="ys-panel-header ys-panel-header--flex">
            Registered MCP Servers (${this._servers.length})
            <button class="ys-btn ys-btn-header"
                    @click=${() => { this._showImport = true; this._importError = ''; }}>
              Import server
            </button>
          </div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">
              MCP servers onboarded through the capability-envelope import ceremony.
              Each server is pinned to an approved tool surface (effect classes + egress posture).
              Tool-surface drift is blocked and queued for re-approval below.
            </div>
            ${this._servers.length === 0
              ? html`<div class="ys-txt-note">
                  No MCP servers registered yet.
                  In demo mode, run <code>python3 scripts/populate-demo.py</code> to seed the cloud-9 demo server,
                  or click <strong>Import server</strong> to onboard one manually.
                </div>`
              : html`<table class="ys-table">
                  <thead>
                    <tr>
                      <th>Server</th><th>Tools</th><th>Egress</th>
                      <th>Topology</th><th>Envelope</th><th>Approved by</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${this._servers.map((s) => this._renderServerRow(s))}
                  </tbody>
                </table>`}
          </div>
        </div>

        <!-- Panel 2: Tool-surface re-approval queue -->
        <div class="ys-panel ys-panel--mt">
          <div class="ys-panel-header">
            MCP tool-surface re-approvals (${this._pending.length})
            ${this._pending.length ? html`<span class="ys-badge ys-badge-amber">action required</span>` : nothing}
          </div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">
              When a registered MCP server's tool surface drifts from its approved baseline,
              the refresh is blocked (fail-closed) until you re-pin a new baseline or reject.
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
                        <td>
                          <button class="ys-btn" data-act="view"
                                  @click=${() => this._openDiff(r)}>
                            Review diff
                          </button>
                        </td>
                      </tr>`)}
                  </tbody>
                </table>`}
          </div>
        </div>

        ${this._renderDiffModal()}
        ${this._renderImportModal()}
      </div>`;
  }
}

customElements.define('ys-admin-mcp', YsAdminMcp);

registerAdminModule({
  id: 'mcp',
  label: 'MCP Registry',
  icon: '⧉',
  order: 30,
  group: 'agents',
  render: (ctx) => html`<ys-admin-mcp .api=${ctx.api} .app=${ctx.app}></ys-admin-mcp>`,
});
