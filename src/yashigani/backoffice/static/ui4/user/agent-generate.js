// Yashigani 4.0 user app — <ys-agent-generate> (no-code, NL-driven agent creation).
//
// Surface 3 of the 4.0 agent-builder. The user DESCRIBES, in plain language, what
// an agent should do; our LLM + Langflow turn that into a flow; the user REVIEWS a
// preview and then EXPLICITLY clicks "Add to my agent templates". Nothing is ever
// added without that click (human-in-the-loop — EU AI Act Art.14 posture: the AI
// recommends, the human decides and is the logged accountable act).
//
// PINNED CONTRACT (backend built in parallel by Tom):
//   POST /user/agents/generate {description}
//        → { flow_id, summary, graph, draft:true }
//   POST /user/agents  {name, description, flow_id, graph, summary, draft:false}
//        → { ua_id, ... }                       (commit the reviewed draft)
//
// SECURITY (RISK-105/106/096):
//   - The `summary` is LLM-authored from the user's free text → UNTRUSTED. It only
//     ever reaches the DOM through Lit text interpolation (auto-escaped to
//     textContent) — never an innerHTML sink, never the markdown pipeline-as-HTML.
//   - The `graph` is rendered READ-ONLY through ui4/core/drawflow-safe.js
//     (mountDrawflowSafe + importSafe), which routes EVERY node label through
//     DOMPurify/Trusted-Types (RISK-096). We never touch Drawflow's native sinks.
//   - ONE ApiClient(sessionKind:'user'); the app never parses error bodies by hand
//     and never sanitises by hand outside the pinned seam.
import { ApiClient, installTrustedTypes, widgets, sanitizeLabel } from '/static/ui4/core/index.js';
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

installTrustedTypes();
void widgets;

const DRAWFLOW_SAFE = '/static/ui4/core/drawflow-safe.js';

export class YsAgentGenerate extends LitElement {
  static properties = {
    _phase: { state: true },   // 'idle' | 'generating' | 'preview' | 'adding'
    _preview: { state: true }, // { flow_id, summary, graph, draft } | null
    _seam: { state: true },    // 'unknown' | 'ready' | 'missing'
    _busy: { state: true },
  };

  constructor() {
    super();
    this._phase = 'idle';
    this._preview = null;
    this._seam = 'unknown';
    this._busy = false;
    this._editor = null;
    this._graphRendered = false;
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

  _val(sel) {
    const el = this.querySelector(sel);
    return el ? String(el.value || '') : '';
  }

  // ── generate (recommend) ────────────────────────────────────
  async _generate() {
    if (this._busy) return;
    const description = this._val('#ys-gen-desc').trim();
    if (!description) { this._notify('Describe what your agent should do first.', 'error'); return; }
    this._busy = true;
    this._phase = 'generating';
    const res = await this.api.mutate('/user/agents/generate', { method: 'POST', body: { description } });
    this._busy = false;
    if (!res.ok) {
      this._phase = 'idle';
      this._notify(res.error ? res.error.message : 'Could not generate a flow.', 'error');
      return;
    }
    const d = res.data || {};
    // Draft preview ONLY — nothing is added to the user's templates yet.
    this._preview = {
      flow_id: d.flow_id || '',
      summary: typeof d.summary === 'string' ? d.summary : '',
      graph: (d.graph && typeof d.graph === 'object') ? d.graph : null,
      draft: d.draft !== false,
    };
    this._graphRendered = false;
    this._phase = 'preview';
  }

  // ── refine / regenerate ─────────────────────────────────────
  _refine() {
    // Return to the editable description (kept intact) and discard the draft.
    this._teardownGraph();
    this._preview = null;
    this._phase = 'idle';
  }

  // ── add (the human decision — commit the reviewed draft) ─────
  async _add() {
    if (this._busy || !this._preview) return;
    const name = this._val('#ys-gen-name').trim();
    if (!name) { this._notify('Give the agent a name before adding it.', 'error'); return; }
    this._busy = true;
    this._phase = 'adding';
    // The generated spec, committed by an explicit human action (draft:false).
    const body = {
      name,
      description: this._val('#ys-gen-summary-edit').trim() || this._preview.summary,
      flow_id: this._preview.flow_id,
      graph: this._preview.graph,
      summary: this._preview.summary,
      draft: false,
    };
    const res = await this.api.mutate('/user/agents', { method: 'POST', body });
    this._busy = false;
    if (!res.ok) {
      this._phase = 'preview';
      this._notify(res.error ? res.error.message : 'Could not add the agent.', 'error');
      return;
    }
    const rejected = (res.data && res.data.rejected_skills) || [];
    this._notify(
      `Added to your agent templates${rejected.length ? ` — ${rejected.length} skill(s) outside your ceiling were dropped` : ''}.`,
      'success',
    );
    // Tell the parent (agent-manager) to reload its list and select the new agent.
    this.dispatchEvent(new CustomEvent('ys-agent-added', {
      bubbles: true,
      composed: true,
      detail: { ua_id: res.data && res.data.ua_id ? res.data.ua_id : '' },
    }));
    this._teardownGraph();
    this._preview = null;
    this._phase = 'idle';
    const descEl = this.querySelector('#ys-gen-desc');
    if (descEl) descEl.value = '';
  }

  // ── read-only graph render (RISK-096 seam) ──────────────────
  updated() {
    if (this._phase === 'preview' && this._preview && this._preview.graph && !this._graphRendered) {
      this._graphRendered = true; // guard against re-entrant renders
      this._renderGraph();
    }
  }

  async _renderGraph() {
    const host = this.querySelector('.ys-gen-graph-host');
    if (!host) { this._seam = 'missing'; return; }
    try {
      const mod = await import(DRAWFLOW_SAFE);
      if (!mod || typeof mod.mountDrawflowSafe !== 'function'
          || typeof mod.importSafe !== 'function' || typeof mod.registerNodeTypeSafe !== 'function') {
        this._seam = 'missing';
        return;
      }
      this._editor = mod.mountDrawflowSafe(host);
      // Read-only preview: the user reviews, they do not edit the canvas here.
      this._editor.editor_mode = 'fixed';
      // importSafe forces typenode=true (cloneNode path, no innerHTML). That path
      // requires every node "html" key to be a registered template, so register a
      // safe generic template for each node type present in the generated graph.
      this._registerGraphNodeTypes(mod, this._preview.graph);
      // importSafe sanitises EVERY node label via DOMPurify/Trusted-Types (RISK-096);
      // labels bind through readonly inputs (.value), never an innerHTML sink.
      mod.importSafe(this._editor, this._preview.graph);
      this._seam = 'ready';
    } catch (err) {
      // Seam not deployed / un-importable graph — degrade to the text summary only.
      this._seam = 'missing';
    }
  }

  // Register a safe, developer-authored template for each distinct node type
  // ("html" key) found in the generated graph. The label is bound by Drawflow via
  // a READONLY <input df-label> (value assignment — not innerHTML), and the type
  // caption is set via textContent. No untrusted string reaches a markup sink.
  _registerGraphNodeTypes(mod, graph) {
    const seen = new Set();
    const df = graph && graph.drawflow;
    if (!df || typeof df !== 'object') return;
    for (const moduleName of Object.keys(df)) {
      const data = df[moduleName] && df[moduleName].data;
      if (!data) continue;
      for (const node of Object.values(data)) {
        const key = node && typeof node.html === 'string' ? node.html : '';
        if (!key || seen.has(key)) continue;
        seen.add(key);
        const tpl = document.createElement('div');
        tpl.className = 'ys-gen-node';
        const cap = document.createElement('div');
        cap.className = 'ys-gen-node-type';
        cap.textContent = key;                 // type identifier — textContent, inert
        const label = document.createElement('input');
        label.className = 'ys-gen-node-label';
        label.setAttribute('df-label', '');    // Drawflow binds node.data.label → .value
        label.readOnly = true;
        tpl.appendChild(cap);
        tpl.appendChild(label);
        try { mod.registerNodeTypeSafe(this._editor, key, tpl); } catch (e) { /* skip */ }
      }
    }
  }

  _teardownGraph() {
    if (this._editor && typeof this._editor.clear === 'function') {
      try { this._editor.clear(); } catch (e) { /* best-effort */ }
    }
    this._editor = null;
    this._graphRendered = false;
    this._seam = 'unknown';
  }

  // ── render ──────────────────────────────────────────────────
  _renderComposer() {
    const generating = this._phase === 'generating';
    return html`
      <div class="ys-card ys-gen-panel">
        <div class="ys-builder-h">Describe what your agent should do</div>
        <div class="ys-builder-sub">
          Write it in plain language. We turn it into a governed agent flow and show you a
          preview to review — nothing is added to your templates until you say so.
        </div>
        <div class="ys-form-row">
          <textarea id="ys-gen-desc" class="ys-textarea ys-gen-desc" rows="5" maxlength="2000"
                    ?disabled=${generating}
                    placeholder="e.g. An assistant that reads my uploaded PDFs, summarises each one, and drafts a weekly digest email."></textarea>
        </div>
        <div class="ys-form-actions">
          <button class="ys-btn ys-gen-submit" ?disabled=${this._busy} @click=${() => this._generate()}>
            ${generating ? 'Generating…' : 'Generate preview'}
          </button>
        </div>
        ${generating
          ? html`<div class="ys-txt-note ys-gen-loading" role="status" aria-live="polite">Building your agent flow…</div>`
          : nothing}
      </div>`;
  }

  _renderPreview() {
    const p = this._preview;
    const defaultName = sanitizeLabel(this._deriveName(p.summary));
    return html`
      <div class="ys-card ys-gen-preview">
        <div class="ys-builder-h">Review your generated agent <span class="ys-gen-draft-tag">Draft</span></div>
        <div class="ys-builder-sub">
          This is a draft. Review it below, then add it to your templates — or refine your description and regenerate.
        </div>

        <div class="ys-form-row">
          <label class="ys-label">What this agent will do</label>
          <!-- Untrusted LLM text — Lit interpolation renders it as textContent (auto-escaped). -->
          <p class="ys-gen-summary">${p.summary || 'No summary returned.'}</p>
        </div>

        ${p.graph
          ? html`
            <div class="ys-form-row">
              <label class="ys-label">Generated flow (read-only)</label>
              <div class="ys-gen-graph-host ys-drawflow-host"></div>
              ${this._seam === 'missing'
                ? html`<div class="ys-txt-note">Flow preview is unavailable — review the description above.</div>`
                : nothing}
            </div>`
          : nothing}

        <div class="ys-form-row">
          <label class="ys-label">Name</label>
          <input id="ys-gen-name" class="ys-input" maxlength="128" .value=${defaultName}
                 placeholder="Name this agent">
        </div>
        <div class="ys-form-row">
          <label class="ys-label">Description (optional)</label>
          <input id="ys-gen-summary-edit" class="ys-input" maxlength="512"
                 placeholder="Short description (defaults to the summary above)">
        </div>

        <div class="ys-form-actions">
          <button class="ys-btn ys-gen-add" ?disabled=${this._busy} @click=${() => this._add()}>
            ${this._phase === 'adding' ? 'Adding…' : 'Add to my agent templates'}
          </button>
          <button class="ys-btn ys-btn-secondary ys-gen-refine" ?disabled=${this._busy} @click=${() => this._refine()}>
            Refine description
          </button>
        </div>
      </div>`;
  }

  _deriveName(summary) {
    const first = String(summary || '').split(/[\n.!?]/)[0].trim();
    return first ? first.slice(0, 80) : '';
  }

  render() {
    return html`
      <div class="ys-builder-col ys-gen-col">
        ${this._phase === 'preview' || this._phase === 'adding'
          ? this._renderPreview()
          : this._renderComposer()}
      </div>`;
  }
}

customElements.define('ys-agent-generate', YsAgentGenerate);
