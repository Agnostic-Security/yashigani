// Yashigani 4.0 user app — <ys-builder-app> (visual / Drawflow agent builder).
//
// Surface 2 of the 4.0 agent-builder: an n8n-style canvas where nodes are
// tools / models / agents / policies / IO and edges are governed hops. The
// canvas emits OUR agent-template spec and POSTs it to /user/agents.
//
// PINNED SEAM (Su — feat/4.0-csp-vendoring): Drawflow is vendored same-origin at
//   /static/vendor/drawflow/drawflow.esm.js
// and mounted ONLY through ui4/core/drawflow-safe.js (mountDrawflowSafe), which
// routes EVERY node label through DOMPurify/Trusted-Types (sanitizeLabel +
// textContent) — RISK-096. We NEVER write raw labels and NEVER fall back to
// Drawflow's native addNode (innerHTML sink). If the seam is not present yet,
// this surface degrades to a clear "pending vendor seam" notice (feature flag)
// rather than white-screening — see _seam state below.
//
// Robustness: we keep our OWN node registry (_nodes) as we add nodes, so the
// agent-template spec derivation does NOT depend on the seam's export shape —
// only on mountDrawflowSafe(host) + editor.addNodeSafe({...}). The visual graph
// is persisted client-side (localStorage) as the template; backend graph
// persistence is a follow-up (CreateAgentBody stores name/persona/skills only).
import { ApiClient, installTrustedTypes, widgets, sanitizeLabel } from '/static/ui4/core/index.js';
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import './session-header.js';

installTrustedTypes();
void widgets;

const DRAWFLOW_SAFE = '/static/ui4/core/drawflow-safe.js';
const TEMPLATE_KEY = 'ys-builder-template';

// Node palette. `io` = input/output; ports are wired as governed hops (edges).
const NODE_TYPES = [
  { type: 'input',  label: 'Input',  inputs: 0, outputs: 1 },
  { type: 'model',  label: 'Model',  inputs: 1, outputs: 1 },
  { type: 'tool',   label: 'Tool',   inputs: 1, outputs: 1 },
  { type: 'agent',  label: 'Agent',  inputs: 1, outputs: 1 },
  { type: 'policy', label: 'Policy', inputs: 1, outputs: 1 },
  { type: 'output', label: 'Output', inputs: 1, outputs: 0 },
];

export class YsBuilderApp extends LitElement {
  static properties = {
    _seam: { state: true },      // 'loading' | 'ready' | 'missing'
    _nodeCount: { state: true },
    _busy: { state: true },
    _username: { state: true },
  };

  constructor() {
    super();
    this._seam = 'loading';
    this._nodeCount = 0;
    this._busy = false;
    this._username = '';
    this._editor = null;
    this._nodes = [];      // [{id, type, label}] — our source of truth for the spec
    this._seq = 0;
    this._toast = null;
    this.api = new ApiClient({
      sessionKind: 'user',
      onStepUp: (spec) => widgets.promptStepUp(spec),
    });
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._toast = document.createElement('ys-toast');
    document.body.appendChild(this._toast);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._toast) this._toast.remove();
  }

  _notify(msg, kind = 'info') { if (this._toast) this._toast.show(msg, kind); }

  async firstUpdated() {
    await this._mountSeam();
  }

  // ── seam mount (Su's drawflow-safe.js) ─────────────────────
  async _mountSeam() {
    const host = this.querySelector('.ys-drawflow-host');
    if (!host) { this._seam = 'missing'; return; }
    try {
      const mod = await import(DRAWFLOW_SAFE);
      const mount = mod && mod.mountDrawflowSafe;
      if (typeof mount !== 'function') { this._seam = 'missing'; return; }
      const editor = mount(host);
      // Hard requirement: the safe label sink. We refuse Drawflow's native
      // addNode (innerHTML) — without addNodeSafe we treat the seam as absent.
      if (!editor || typeof editor.addNodeSafe !== 'function') { this._seam = 'missing'; return; }
      this._editor = editor;
      this._seam = 'ready';
    } catch (err) {
      // Vendor seam not deployed yet (Su builds it in parallel) — flag, do not crash.
      this._seam = 'missing';
    }
  }

  // ── node ops ───────────────────────────────────────────────
  _addNode(typeKey, rawLabel) {
    if (this._seam !== 'ready' || !this._editor) return;
    const def = NODE_TYPES.find((t) => t.type === typeKey) || NODE_TYPES[0];
    this._seq += 1;
    // Label is a PLAIN-TEXT identifier. We sanitize defensively here too; the
    // seam guarantees textContent rendering regardless (belt-and-braces). If a
    // user pastes pure markup it sanitises to empty — fall back to a usable
    // default so every node stays identifiable (and no empty skill is emitted).
    const cleaned = sanitizeLabel(String(rawLabel || '')).trim();
    const label = cleaned || `${def.label}-${this._seq}`;
    const posX = 60 + ((this._seq % 5) * 180);
    const posY = 60 + (Math.floor(this._seq / 5) * 120);
    let id;
    try {
      id = this._editor.addNodeSafe({
        type: def.type,
        label,
        inputs: def.inputs,
        outputs: def.outputs,
        posX,
        posY,
        data: { type: def.type, label },
      });
    } catch (err) {
      this._notify('Could not add node.', 'error');
      return;
    }
    this._nodes.push({ id: id != null ? String(id) : `n${this._seq}`, type: def.type, label });
    this._nodeCount = this._nodes.length;
    this._persistTemplate();
  }

  _onAddCustom() {
    const typeEl = this.querySelector('#ys-node-type');
    const labelEl = this.querySelector('#ys-node-label');
    const type = typeEl ? typeEl.value : 'tool';
    const label = labelEl ? labelEl.value : '';
    this._addNode(type, label);
    if (labelEl) labelEl.value = '';
  }

  _clearCanvas() {
    if (this._editor && typeof this._editor.clear === 'function') {
      try { this._editor.clear(); } catch (e) { /* best-effort */ }
    }
    this._nodes = [];
    this._seq = 0;
    this._nodeCount = 0;
    this._persistTemplate();
  }

  // ── template spec derivation + persistence ─────────────────
  _buildTemplate(name) {
    // OUR agent-template spec. The visual graph is the authoring surface; the
    // derived fields below are what the current /user/agents contract stores.
    const tools = this._nodes.filter((n) => n.type === 'tool').map((n) => n.label).filter((s) => s.trim());
    const models = this._nodes.filter((n) => n.type === 'model').map((n) => n.label);
    const policies = this._nodes.filter((n) => n.type === 'policy').map((n) => n.label);
    const sysBits = [];
    if (models.length) sysBits.push(`Preferred models: ${models.join(', ')}.`);
    if (policies.length) sysBits.push(`Governing policies: ${policies.join(', ')}.`);
    return {
      name,
      description: `Visual template — ${this._nodes.length} node(s), ${tools.length} tool(s).`,
      persona: 'I am a Yashigani-governed agent assembled in the visual builder.',
      system_prompt: sysBits.join(' '),
      skills: tools,
      // Full graph retained client-side; surfaced for backend graph persistence.
      _graph: { nodes: this._nodes },
    };
  }

  _persistTemplate() {
    try {
      window.localStorage.setItem(TEMPLATE_KEY, JSON.stringify({ nodes: this._nodes }));
    } catch (e) { /* storage unavailable — graph stays in-memory */ }
  }

  async _saveAgent() {
    if (this._busy) return;
    const nameEl = this.querySelector('#ys-builder-name');
    const name = nameEl ? String(nameEl.value || '').trim() : '';
    if (!name) { this._notify('Give the agent a name before saving.', 'error'); return; }
    if (!this._nodes.length) { this._notify('Add at least one node first.', 'error'); return; }
    const tpl = this._buildTemplate(name);
    // Backend CreateAgentBody fields only (the _graph stays client-side).
    const body = {
      name: tpl.name,
      description: tpl.description,
      persona: tpl.persona,
      system_prompt: tpl.system_prompt,
      skills: tpl.skills,
    };
    this._busy = true;
    const res = await this.api.mutate('/user/agents', { method: 'POST', body });
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Save failed.', 'error'); return; }
    const rejected = (res.data && res.data.rejected_skills) || [];
    this._notify(
      `Agent saved from canvas${rejected.length ? ` — ${rejected.length} tool(s) outside your ceiling were dropped` : ''}.`,
      'success',
    );
  }

  // ── render ─────────────────────────────────────────────────
  _renderToolbar() {
    return html`
      <div class="ys-canvas-toolbar">
        ${NODE_TYPES.map((t) => html`
          <button class="ys-btn ys-btn-secondary ys-add-${t.type}"
                  ?disabled=${this._seam !== 'ready'}
                  @click=${() => this._addNode(t.type)}>+ ${t.label}</button>`)}
        <span class="ys-builder-sub">·</span>
        <select id="ys-node-type" class="ys-select" ?disabled=${this._seam !== 'ready'}>
          ${NODE_TYPES.map((t) => html`<option value=${t.type}>${t.label}</option>`)}
        </select>
        <input id="ys-node-label" class="ys-input ys-node-label-input"
               placeholder="Node label" ?disabled=${this._seam !== 'ready'}>
        <button class="ys-btn ys-add-custom" ?disabled=${this._seam !== 'ready'}
                @click=${() => this._onAddCustom()}>Add node</button>
        <button class="ys-btn ys-btn-ghost ys-clear-canvas" ?disabled=${this._seam !== 'ready'}
                @click=${() => this._clearCanvas()}>Clear</button>
      </div>`;
  }

  _renderSaveBar() {
    return html`
      <div class="ys-canvas-toolbar">
        <input id="ys-builder-name" class="ys-input" maxlength="128" placeholder="Agent name">
        <button class="ys-btn ys-save-template" ?disabled=${this._busy || this._seam !== 'ready'}
                @click=${() => this._saveAgent()}>Export &amp; save agent</button>
        <span class="ys-builder-sub">${this._nodeCount} node(s) on canvas</span>
      </div>`;
  }

  render() {
    return html`
      <div class="ys-app">
        <ys-session-header .username=${this._username} active="builder"></ys-session-header>
        <div class="ys-builder-wrap">
          <div class="ys-builder-h">Visual agent builder</div>
          <div class="ys-builder-sub">
            Drag-free n8n-style canvas: add tools, models, agents, policies and IO; connect them as
            governed hops; then export the template to a real agent. All labels are plain-text identifiers,
            sanitised at the render seam (RISK-096).
          </div>
          ${this._seam === 'missing'
            ? html`<div class="ys-drawflow-host"><div class="ys-seam-missing ys-seam-flag">
                Visual builder is pending the vendored Drawflow seam
                (ui4/core/drawflow-safe.js + /static/vendor/drawflow/, Su — feat/4.0-csp-vendoring).
                The form-based builder under <a href="/agents">Agents</a> is fully available now.
              </div></div>`
            : html`
              ${this._renderToolbar()}
              <div class="ys-drawflow-host"></div>
              ${this._renderSaveBar()}`}
        </div>
      </div>`;
  }
}

customElements.define('ys-builder-app', YsBuilderApp);
