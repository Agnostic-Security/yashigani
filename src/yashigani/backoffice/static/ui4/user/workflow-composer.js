// Yashigani 4.0 user app — <ys-workflow-composer-app> (no-code workflow composer).
//
// Surface 4 of the 4.0 user plane. The user DESCRIBES a workflow in plain
// language using @-handles — e.g.
//   "@Mimi using @mcp2 retrieve the payment information and push it to @api9
//    every 10 minutes"
// — our backend parses it into ordered steps + a schedule; the user REVIEWS the
// preview and then EXPLICITLY clicks "Add workflow". Nothing is ever scheduled or
// committed without that click (human-in-the-loop — EU AI Act Art.14 posture: the
// AI recommends the parse, the human decides and is the logged accountable act).
//
// @-handles cover four kinds: agent | persona | mcp | api. The @-autocomplete
// reuses the shared <ys-mention-menu> widget (now incl. mcp/api kinds) over the
// pinned GET /user/mentions contract.
//
// PINNED CONTRACT (backend built in parallel):
//   GET    /user/mentions
//          → [{handle, kind:"agent"|"persona"|"mcp"|"api", display, id}]
//   POST   /user/workflows/generate {description}
//          → {draft_id, summary, steps:[{actor,action,uses,output_to}],
//             schedule, warnings, draft:true}
//   POST   /user/workflows {draft_id, name}            commit the reviewed draft
//   GET    /user/workflows                             list
//   PATCH  /user/workflows/{id} {enabled}              enable / disable
//   DELETE /user/workflows/{id}                        remove
//   GET    /user/workflows/{id}/runs                   run history
//
// SECURITY (RISK-100/105/106):
//   - ONE ApiClient(sessionKind:'user'); the app never parses error bodies by
//     hand and never sanitises by hand.
//   - EVERY parsed field (summary, step actor/action/uses/output_to, schedule
//     text, warnings, workflow names, run output) is LLM-/upstream-authored →
//     UNTRUSTED. It reaches the DOM ONLY through Lit text interpolation
//     (auto-escaped to textContent) — never an innerHTML sink, never the §3
//     markdown-as-HTML pipeline. No raw HTML anywhere.
//   - @-handles in the textarea are plain text; the mention menu renders them via
//     Lit text bindings only.
import { ApiClient, installTrustedTypes, widgets } from '/static/ui4/core/index.js';
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import './session-header.js';
import './mention-menu.js';

installTrustedTypes();
void widgets;

const MENTIONS_PATH = '/user/mentions';
const WORKFLOWS_PATH = '/user/workflows';

export class YsWorkflowComposerApp extends LitElement {
  static properties = {
    _phase: { state: true },       // 'compose' | 'generating' | 'preview' | 'adding'
    _draft: { state: true },       // {draft_id, summary, steps, schedule, warnings} | null
    _workflows: { state: true },   // [{id, name, schedule, enabled}]
    _runsOpenId: { state: true },  // id of the workflow whose runs are shown ('' = none)
    _runs: { state: true },        // run-history rows for _runsOpenId
    _busy: { state: true },
    _username: { state: true },
    // @-mention autocomplete state (mirrors <ys-chat-view>).
    _mentionOpen: { state: true },
    _mentionFiltered: { state: true },
    _mentionActive: { state: true },
  };

  constructor() {
    super();
    this._phase = 'compose';
    this._draft = null;
    this._workflows = [];
    this._runsOpenId = '';
    this._runs = [];
    this._busy = false;
    this._username = '';
    this._mentionOpen = false;
    this._mentionFiltered = [];
    this._mentionActive = 0;
    // @-mention cache (null = not yet fetched); the promise de-dupes concurrent
    // fetches so fast typing cannot fire the request twice.
    this._mentions = null;
    this._mentionsPromise = null;
    this._mentionStart = 0;
    this.api = new ApiClient({
      sessionKind: 'user',
      onStepUp: (spec) => widgets.promptStepUp(spec),
    });
    this._toast = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._toast = document.createElement('ys-toast');
    document.body.appendChild(this._toast);
    this._reloadWorkflows();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._toast) this._toast.remove();
  }

  _notify(msg, kind = 'info') { if (this._toast) this._toast.show(msg, kind); }

  get _input() { return this.querySelector('.ys-wf-input'); }

  _val(sel) {
    const el = this.querySelector(sel);
    return el ? String(el.value || '') : '';
  }

  // ── data load ──────────────────────────────────────────────
  _coerceWorkflows(payload) {
    let arr = [];
    if (Array.isArray(payload)) arr = payload;
    else if (payload && typeof payload === 'object') {
      if (Array.isArray(payload.workflows)) arr = payload.workflows;
      else if (Array.isArray(payload.items)) arr = payload.items;
      else if (Array.isArray(payload.data)) arr = payload.data;
    }
    return arr.map((w) => ({
      id: String(w.id ?? w.workflow_id ?? w.wf_id ?? w.uuid ?? ''),
      name: String(w.name ?? w.title ?? '(unnamed workflow)'),
      schedule: w.schedule ?? w.schedule_text ?? null,
      enabled: w.enabled ?? w.is_enabled ?? w.active ?? false,
    })).filter((w) => w.id);
  }

  async _reloadWorkflows() {
    const data = await this.api.get(WORKFLOWS_PATH);
    this._workflows = this._coerceWorkflows(data);
  }

  // ── @-mention autocomplete (over agent|persona|mcp|api) ─────
  _ensureMentions() {
    if (!this._mentionsPromise) {
      this._mentionsPromise = (async () => {
        if (!this.api) return [];
        const data = await this.api.get(MENTIONS_PATH);
        const list = Array.isArray(data)
          ? data
          : (data && Array.isArray(data.items) ? data.items
            : (data && Array.isArray(data.data) ? data.data : []));
        this._mentions = list;
        return list;
      })();
    }
    return this._mentionsPromise;
  }

  // Detect an active "@token" immediately left of the caret and open/refilter
  // the menu. Called on every textarea input.
  async _syncMention() {
    const ta = this._input;
    if (!ta) return;
    const caret = ta.selectionStart;
    const left = ta.value.slice(0, caret);
    const m = /(?:^|\s)@([^\s@]*)$/.exec(left);
    if (!m) { this._closeMention(); return; }
    this._mentionStart = caret - m[1].length - 1; // position of the '@'
    const q = m[1].toLowerCase();
    const items = await this._ensureMentions();
    // The caret may have moved while the fetch was in flight; re-validate.
    if (!/(?:^|\s)@[^\s@]*$/.test(ta.value.slice(0, ta.selectionStart))) {
      this._closeMention();
      return;
    }
    this._mentionFiltered = items.filter((it) => {
      const h = String((it && it.handle) ?? '').toLowerCase();
      const d = String((it && it.display) ?? '').toLowerCase();
      return !q || h.includes(q) || d.includes(q);
    });
    this._mentionActive = 0;
    this._mentionOpen = this._mentionFiltered.length > 0;
  }

  _closeMention() {
    this._mentionOpen = false;
    this._mentionFiltered = [];
    this._mentionActive = 0;
  }

  // Insert "@handle " over the active @token and close the menu.
  _pickMention(item) {
    const ta = this._input;
    if (!ta || !item) return;
    const handle = String(item.handle ?? '');
    const before = ta.value.slice(0, this._mentionStart);
    const after = ta.value.slice(ta.selectionStart);
    const insert = `@${handle} `;
    ta.value = `${before}${insert}${after}`;
    const pos = before.length + insert.length;
    ta.setSelectionRange(pos, pos);
    this._closeMention();
    ta.focus();
  }

  _onKeydown(e) {
    // While the mention menu is open it captures navigation/commit keys.
    if (this._mentionOpen && this._mentionFiltered.length) {
      const n = this._mentionFiltered.length;
      if (e.key === 'ArrowDown') { e.preventDefault(); this._mentionActive = (this._mentionActive + 1) % n; return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); this._mentionActive = (this._mentionActive - 1 + n) % n; return; }
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); this._pickMention(this._mentionFiltered[this._mentionActive]); return; }
      if (e.key === 'Escape') { e.preventDefault(); this._closeMention(); return; }
    }
  }

  // ── generate (recommend) ───────────────────────────────────
  async _generate() {
    if (this._busy) return;
    const description = (this._input ? this._input.value : '').trim();
    if (!description) { this._notify('Describe your workflow first.', 'error'); return; }
    this._busy = true;
    this._phase = 'generating';
    this._closeMention();
    const res = await this.api.mutate(`${WORKFLOWS_PATH}/generate`, {
      method: 'POST', body: { description },
    });
    this._busy = false;
    if (!res.ok) {
      this._phase = 'compose';
      this._notify(res.error ? res.error.message : 'Could not parse that workflow.', 'error');
      return;
    }
    const d = res.data || {};
    // Draft preview ONLY — nothing is committed or scheduled yet.
    this._draft = {
      draft_id: String(d.draft_id ?? d.flow_id ?? ''),
      summary: typeof d.summary === 'string' ? d.summary : '',
      steps: Array.isArray(d.steps) ? d.steps : [],
      schedule: d.schedule ?? null,
      warnings: Array.isArray(d.warnings) ? d.warnings : [],
    };
    this._phase = 'preview';
  }

  // ── refine (discard the draft, keep the description) ────────
  _refine() {
    this._draft = null;
    this._phase = 'compose';
    if (this._input) this._input.focus();
  }

  // ── add (the human decision — commit the reviewed draft) ────
  async _add() {
    if (this._busy || !this._draft) return;
    const name = this._val('.ys-wf-name').trim();
    if (!name) { this._notify('Name the workflow before adding it.', 'error'); return; }
    this._busy = true;
    this._phase = 'adding';
    const res = await this.api.mutate(WORKFLOWS_PATH, {
      method: 'POST', body: { draft_id: this._draft.draft_id, name },
    });
    this._busy = false;
    if (!res.ok) {
      this._phase = 'preview';
      this._notify(res.error ? res.error.message : 'Could not add the workflow.', 'error');
      return;
    }
    this._notify('Workflow added.', 'success');
    this._draft = null;
    this._phase = 'compose';
    const ta = this._input;
    if (ta) ta.value = '';
    await this._reloadWorkflows();
  }

  // ── list actions ───────────────────────────────────────────
  async _toggle(w) {
    if (this._busy) return;
    const next = !w.enabled;
    const res = await this.api.mutate(`${WORKFLOWS_PATH}/${encodeURIComponent(w.id)}`, {
      method: 'PATCH', body: { enabled: next },
    });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Update failed.', 'error'); return; }
    this._workflows = this._workflows.map(
      (x) => (x.id === w.id ? { ...x, enabled: next } : x),
    );
    this._notify(next ? 'Workflow enabled.' : 'Workflow disabled.', 'success');
  }

  async _delete(w) {
    if (this._busy) return;
    if (!window.confirm(`Delete workflow "${w.name}"? This cannot be undone.`)) return;
    const res = await this.api.mutate(`${WORKFLOWS_PATH}/${encodeURIComponent(w.id)}`, { method: 'DELETE' });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Delete failed.', 'error'); return; }
    this._notify('Workflow deleted.', 'success');
    if (this._runsOpenId === w.id) { this._runsOpenId = ''; this._runs = []; }
    await this._reloadWorkflows();
  }

  async _openRuns(w) {
    if (this._runsOpenId === w.id) { this._runsOpenId = ''; this._runs = []; return; }
    this._runsOpenId = w.id;
    this._runs = [];
    const data = await this.api.get(`${WORKFLOWS_PATH}/${encodeURIComponent(w.id)}/runs`);
    let arr = [];
    if (Array.isArray(data)) arr = data;
    else if (data && Array.isArray(data.runs)) arr = data.runs;
    else if (data && Array.isArray(data.items)) arr = data.items;
    this._runs = arr;
  }

  // ── presentation helpers (all → text, never markup) ─────────
  _fieldText(v) {
    if (v == null) return '';
    if (Array.isArray(v)) return v.map((x) => String(x)).join(', ');
    if (typeof v === 'object') return String(v.handle ?? v.name ?? v.id ?? JSON.stringify(v));
    return String(v);
  }

  _scheduleText(schedule) {
    if (schedule == null || schedule === '') return 'No schedule — runs on manual trigger only.';
    if (typeof schedule === 'string') return schedule;
    if (typeof schedule === 'object') {
      const cand = schedule.summary ?? schedule.description ?? schedule.text
        ?? schedule.every ?? schedule.cron ?? schedule.expression;
      if (cand != null) return String(cand);
      return Object.entries(schedule).map(([k, v]) => `${k}: ${String(v)}`).join(', ');
    }
    return String(schedule);
  }

  // ── render: workflow list rail ─────────────────────────────
  _renderList() {
    return html`
      <div class="ys-builder-col">
        <div class="ys-builder-h">Your workflows</div>
        <div class="ys-wf-list ys-ablist">
          ${this._workflows.length === 0
            ? html`<div class="ys-txt-note">No workflows yet. Describe one to begin.</div>`
            : this._workflows.map((w) => html`
                <div class="ys-wf-item ys-ablist-item" data-wf=${w.id}>
                  <div class="ys-wf-item-head">
                    <span class="ys-ablist-name">${w.name}</span>
                    <label class="ys-wf-switch">
                      <input type="checkbox" class="ys-wf-toggle"
                             .checked=${!!w.enabled}
                             @change=${() => this._toggle(w)}>
                      <span>${w.enabled ? 'On' : 'Off'}</span>
                    </label>
                  </div>
                  <div class="ys-ablist-meta">${this._scheduleText(w.schedule)}</div>
                  <div class="ys-wf-item-actions">
                    <button class="ys-btn ys-btn-ghost ys-wf-runs-open"
                            @click=${() => this._openRuns(w)}>
                      ${this._runsOpenId === w.id ? 'Hide runs' : 'View runs'}
                    </button>
                    <button class="ys-btn ys-btn-ghost ys-wf-delete"
                            @click=${() => this._delete(w)}>Delete</button>
                  </div>
                  ${this._runsOpenId === w.id ? this._renderRuns() : nothing}
                </div>`)}
        </div>
      </div>`;
  }

  // ── render: run history ────────────────────────────────────
  _renderRuns() {
    const runs = Array.isArray(this._runs) ? this._runs : [];
    return html`
      <div class="ys-wf-runs">
        <div class="ys-builder-sub">Run history</div>
        ${runs.length === 0
          ? html`<div class="ys-txt-note">No runs recorded yet.</div>`
          : html`
            <table class="ys-table ys-wf-runs-table">
              <thead><tr><th>When</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>
                ${runs.map((r) => {
                  const when = String(r.started_at ?? r.timestamp ?? r.time ?? r.created_at ?? '—');
                  const status = String(r.status ?? r.result ?? r.state ?? '—');
                  // Run output may carry @api/@mcp result payloads → UNTRUSTED;
                  // rendered as text via Lit interpolation (never markup).
                  const detail = this._fieldText(r.output ?? r.detail ?? r.message ?? r.error ?? '');
                  const cls = /fail|error|block/i.test(status) ? 'ys-badge-red'
                    : (/ok|success|done|complete/i.test(status) ? 'ys-badge-green' : 'ys-badge-blue');
                  return html`
                    <tr class="ys-wf-run">
                      <td>${when}</td>
                      <td><span class="ys-badge ${cls}">${status}</span></td>
                      <td class="ys-wf-run-detail">${detail}</td>
                    </tr>`;
                })}
              </tbody>
            </table>`}
      </div>`;
  }

  // ── render: composer ───────────────────────────────────────
  _renderComposer() {
    const generating = this._phase === 'generating';
    return html`
      <div class="ys-card ys-wf-compose">
        <div class="ys-builder-h">Describe a workflow</div>
        <div class="ys-builder-sub">
          Write it in plain language and address agents, personas, MCPs and APIs with
          <code>@</code>. We parse it into ordered steps and a schedule for you to review —
          nothing is added or scheduled until you click <strong>Add workflow</strong>.
        </div>
        <div class="ys-form-row ys-wf-input-col">
          ${this._mentionOpen
            ? html`<ys-mention-menu
                     .items=${this._mentionFiltered}
                     .active=${this._mentionActive}
                     @ys-mention-pick=${(e) => this._pickMention(e.detail.item)}
                     @ys-mention-active=${(e) => { this._mentionActive = e.detail.index; }}></ys-mention-menu>`
            : nothing}
          <textarea class="ys-textarea ys-wf-input" rows="4" maxlength="2000"
                    ?disabled=${generating}
                    placeholder="e.g. @Mimi using @mcp2 retrieve the payment information and push it to @api9 every 10 minutes"
                    @keydown=${(e) => this._onKeydown(e)}
                    @input=${() => this._syncMention()}
                    @blur=${() => this._closeMention()}></textarea>
        </div>
        <div class="ys-form-actions">
          <button class="ys-btn ys-wf-generate" ?disabled=${this._busy} @click=${() => this._generate()}>
            ${generating ? 'Parsing…' : 'Generate preview'}
          </button>
        </div>
        ${generating
          ? html`<div class="ys-txt-note" role="status" aria-live="polite">Parsing your workflow…</div>`
          : nothing}
      </div>`;
  }

  // ── render: preview ────────────────────────────────────────
  _renderPreview() {
    const d = this._draft;
    const steps = Array.isArray(d.steps) ? d.steps : [];
    const warnings = Array.isArray(d.warnings) ? d.warnings : [];
    return html`
      <div class="ys-card ys-wf-preview">
        <div class="ys-builder-h">Review your workflow <span class="ys-gen-draft-tag">Draft</span></div>
        <div class="ys-builder-sub">
          This is a parsed draft. Review the steps and schedule, then add it — or refine your
          description and regenerate.
        </div>

        ${d.summary
          ? html`<div class="ys-form-row">
              <label class="ys-label">Summary</label>
              <!-- Untrusted parse output → Lit text interpolation (auto-escaped). -->
              <p class="ys-wf-summary">${d.summary}</p>
            </div>`
          : nothing}

        <div class="ys-form-row">
          <label class="ys-label">Steps</label>
          ${steps.length === 0
            ? html`<div class="ys-txt-note">No steps were parsed from your description.</div>`
            : html`<ol class="ys-wf-steps">
                ${steps.map((s) => html`
                  <li class="ys-wf-step">
                    <span class="ys-wf-step-actor">${this._fieldText(s.actor)}</span>
                    <span class="ys-wf-step-action">${this._fieldText(s.action)}</span>
                    ${s.uses != null && this._fieldText(s.uses)
                      ? html`<span class="ys-wf-step-uses">using ${this._fieldText(s.uses)}</span>`
                      : nothing}
                    ${s.output_to != null && this._fieldText(s.output_to)
                      ? html`<span class="ys-wf-step-output">→ ${this._fieldText(s.output_to)}</span>`
                      : nothing}
                  </li>`)}
              </ol>`}
        </div>

        <div class="ys-form-row">
          <label class="ys-label">Schedule</label>
          <div class="ys-wf-schedule">${this._scheduleText(d.schedule)}</div>
        </div>

        ${warnings.length
          ? html`<div class="ys-form-row">
              <label class="ys-label">Warnings</label>
              <ul class="ys-wf-warnings">
                ${warnings.map((w) => html`<li class="ys-wf-warning">${this._fieldText(w)}</li>`)}
              </ul>
            </div>`
          : nothing}

        <div class="ys-form-row">
          <label class="ys-label">Name</label>
          <input class="ys-input ys-wf-name" maxlength="128" placeholder="Name this workflow">
        </div>

        <div class="ys-form-actions">
          <button class="ys-btn ys-wf-add" ?disabled=${this._busy} @click=${() => this._add()}>
            ${this._phase === 'adding' ? 'Adding…' : 'Add workflow'}
          </button>
          <button class="ys-btn ys-btn-secondary ys-wf-refine" ?disabled=${this._busy} @click=${() => this._refine()}>
            Refine description
          </button>
        </div>
      </div>`;
  }

  _renderMain() {
    return html`
      <div class="ys-builder-col">
        ${this._renderComposer()}
        ${(this._phase === 'preview' || this._phase === 'adding') && this._draft
          ? this._renderPreview()
          : nothing}
      </div>`;
  }

  render() {
    return html`
      <div class="ys-app">
        <ys-session-header .username=${this._username} active="workflows"></ys-session-header>
        <div class="ys-builder-wrap">
          <div class="ys-builder-grid">
            ${this._renderList()}
            ${this._renderMain()}
          </div>
        </div>
      </div>`;
  }
}

customElements.define('ys-workflow-composer-app', YsWorkflowComposerApp);
