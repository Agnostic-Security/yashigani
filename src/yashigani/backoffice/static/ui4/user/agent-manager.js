// Yashigani 4.0 user app — <ys-agent-manager-app> (form-based agent builder).
//
// Surface 1 of the 4.0 agent-builder. Lets a user make "personality + skills +
// multiple task-memories" real, entirely through the BOLA-enforced user routes:
//   GET/POST   /user/agents                         list / create
//   GET/PATCH/DELETE /user/agents/{id}              read / rename / delete
//   GET/PUT    /user/agents/{id}/personality        persona + system prompt
//   GET/PUT    /user/agents/{id}/skills             scope-bounded skill set
//   GET        /user/agents/{id}/memories           attached memory blocks
//   POST/DEL   /user/agents/{id}/memories/{blockId} attach / detach
//   GET/POST   /user/memories                        list / create memory blocks
//   PATCH/DEL  /user/memories/{id}                   rename / update / delete
//   GET        /user/skills                          catalog ∩ user ceiling
//
// Shared-layer discipline (RISK-100/105/106): ONE ApiClient(sessionKind:'user');
// every untrusted string (agent name, skill id, memory label/value) reaches the
// DOM only via Lit auto-escaping (textContent). The app never touches a DOM
// sink, never parses error bodies (ApiClient does), never sanitises by hand.
import { ApiClient, installTrustedTypes, widgets } from '/static/ui4/core/index.js';
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import './session-header.js';

installTrustedTypes();
void widgets;

export class YsAgentManagerApp extends LitElement {
  static properties = {
    _agents: { state: true },
    _skills: { state: true },
    _memories: { state: true },
    _selectedId: { state: true },
    _selected: { state: true },
    _agentMemIds: { state: true },   // Set<string>
    _declared: { state: true },      // Set<string> — skill edit buffer
    _rejected: { state: true },      // string[] — last skills PUT rejections
    _creating: { state: true },
    _busy: { state: true },
    _username: { state: true },
  };

  constructor() {
    super();
    this._agents = [];
    this._skills = [];
    this._memories = [];
    this._selectedId = '';
    this._selected = null;
    this._agentMemIds = new Set();
    this._declared = new Set();
    this._rejected = [];
    this._creating = false;
    this._busy = false;
    this._username = '';
    this.api = new ApiClient({
      sessionKind: 'user',
      onStepUp: (spec) => widgets.promptStepUp(spec),
    });
    this._toast = null;
    this._formAgentId = null;  // tracks which agent the editor inputs hold
  }

  createRenderRoot() { return this; }

  // Editor text inputs are populated imperatively (below) keyed on the selected
  // agent id, NOT via reactive .value bindings — otherwise an unrelated re-render
  // (e.g. toggling a skill chip) would clobber the user's unsaved text edits.
  updated() {
    const a = this._selected;
    const id = a ? a.ua_id : '';
    if (id !== this._formAgentId) {
      this._formAgentId = id;
      if (a) {
        const set = (sel, v) => { const el = this.querySelector(sel); if (el) el.value = v || ''; };
        set('#ys-edit-name', a.name);
        set('#ys-edit-desc', a.description);
        set('#ys-edit-persona', a.personality && a.personality.persona);
        set('#ys-edit-sysprompt', a.personality && a.personality.system_prompt);
      }
    }
  }

  connectedCallback() {
    super.connectedCallback();
    this._toast = document.createElement('ys-toast');
    document.body.appendChild(this._toast);
    this._reload();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._toast) this._toast.remove();
  }

  _notify(msg, kind = 'info') { if (this._toast) this._toast.show(msg, kind); }

  // ── data load ──────────────────────────────────────────────
  async _reload() {
    const [agents, skills, memories] = await Promise.all([
      this.api.get('/user/agents'),
      this.api.get('/user/skills'),
      this.api.get('/user/memories'),
    ]);
    this._agents = (agents && Array.isArray(agents.agents)) ? agents.agents : [];
    this._skills = (skills && Array.isArray(skills.available_skills)) ? skills.available_skills : [];
    this._memories = (memories && Array.isArray(memories.memories)) ? memories.memories : [];
    // Keep the current selection live if it still exists.
    if (this._selectedId && this._agents.some((a) => a.ua_id === this._selectedId)) {
      await this._select(this._selectedId);
    } else {
      this._selectedId = '';
      this._selected = null;
    }
  }

  async _select(uaId) {
    this._creating = false;
    const [agent, mem] = await Promise.all([
      this.api.get(`/user/agents/${encodeURIComponent(uaId)}`),
      this.api.get(`/user/agents/${encodeURIComponent(uaId)}/memories`),
    ]);
    if (!agent) { this._notify('Could not load that agent.', 'error'); return; }
    this._selectedId = uaId;
    this._selected = agent;
    this._declared = new Set(Array.isArray(agent.declared_skills) ? agent.declared_skills : []);
    this._rejected = [];
    const blocks = (mem && Array.isArray(mem.memories)) ? mem.memories : [];
    this._agentMemIds = new Set(blocks.map((b) => b.block_id));
  }

  // ── field readers (from the live form, no innerHTML) ───────
  _val(sel) {
    const el = this.querySelector(sel);
    return el ? String(el.value || '') : '';
  }

  // ── agent CRUD ─────────────────────────────────────────────
  _startCreate() {
    this._creating = true;
    this._selectedId = '';
    this._selected = null;
    this._declared = new Set();
    this._rejected = [];
  }

  async _createAgent() {
    if (this._busy) return;
    const name = this._val('#ys-new-name').trim();
    if (!name) { this._notify('Agent name is required.', 'error'); return; }
    this._busy = true;
    const body = {
      name,
      description: this._val('#ys-new-desc'),
      persona: this._val('#ys-new-persona'),
      system_prompt: this._val('#ys-new-sysprompt'),
      skills: [...this._declared],
    };
    const res = await this.api.mutate('/user/agents', { method: 'POST', body });
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Create failed.', 'error'); return; }
    const rejected = (res.data && res.data.rejected_skills) || [];
    this._notify(
      `Agent created${rejected.length ? ` — ${rejected.length} skill(s) outside your ceiling were dropped` : ''}.`,
      'success',
    );
    await this._reload();
    if (res.data && res.data.ua_id) await this._select(res.data.ua_id);
  }

  async _saveBasics() {
    if (!this._selectedId || this._busy) return;
    this._busy = true;
    const res = await this.api.mutate(`/user/agents/${encodeURIComponent(this._selectedId)}`, {
      method: 'PATCH',
      body: { name: this._val('#ys-edit-name').trim(), description: this._val('#ys-edit-desc') },
    });
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Save failed.', 'error'); return; }
    this._notify('Name & description saved.', 'success');
    await this._reload();
  }

  async _savePersonality() {
    if (!this._selectedId || this._busy) return;
    this._busy = true;
    const res = await this.api.mutate(
      `/user/agents/${encodeURIComponent(this._selectedId)}/personality`,
      { method: 'PUT', body: { persona: this._val('#ys-edit-persona'), system_prompt: this._val('#ys-edit-sysprompt') } },
    );
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Save failed.', 'error'); return; }
    this._notify(
      res.data && res.data.letta_synced ? 'Personality saved & synced to Letta.' : 'Personality saved.',
      'success',
    );
    await this._select(this._selectedId);
  }

  async _saveSkills() {
    if (!this._selectedId || this._busy) return;
    this._busy = true;
    const res = await this.api.mutate(
      `/user/agents/${encodeURIComponent(this._selectedId)}/skills`,
      { method: 'PUT', body: { skills: [...this._declared] } },
    );
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Save failed.', 'error'); return; }
    this._rejected = (res.data && res.data.rejected_skills) || [];
    const eff = (res.data && res.data.effective_skills) || [];
    this._notify(
      `Skills saved — ${eff.length} granted${this._rejected.length ? `, ${this._rejected.length} rejected (outside ceiling)` : ''}.`,
      this._rejected.length ? 'info' : 'success',
    );
    await this._select(this._selectedId);
  }

  async _deleteAgent() {
    if (!this._selectedId || this._busy) return;
    const name = this._selected ? this._selected.name : this._selectedId;
    if (!window.confirm(`Delete agent "${name}"? Memory blocks are detached, not deleted.`)) return;
    this._busy = true;
    const res = await this.api.mutate(`/user/agents/${encodeURIComponent(this._selectedId)}`, { method: 'DELETE' });
    this._busy = false;
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Delete failed.', 'error'); return; }
    this._notify('Agent deleted.', 'success');
    this._selectedId = '';
    this._selected = null;
    await this._reload();
  }

  _toggleSkill(skill) {
    const next = new Set(this._declared);
    if (next.has(skill)) next.delete(skill); else next.add(skill);
    this._declared = next;
  }

  // ── memory blocks ──────────────────────────────────────────
  async _createMemory() {
    const label = this._val('#ys-mem-new-label').trim();
    if (!label) { this._notify('Memory label is required.', 'error'); return; }
    const res = await this.api.mutate('/user/memories', {
      method: 'POST', body: { label, value: this._val('#ys-mem-new-value') },
    });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Create failed.', 'error'); return; }
    this._notify('Memory block created.', 'success');
    const labelEl = this.querySelector('#ys-mem-new-label');
    const valEl = this.querySelector('#ys-mem-new-value');
    if (labelEl) labelEl.value = '';
    if (valEl) valEl.value = '';
    await this._reloadMemories();
  }

  async _renameMemory(blockId, currentLabel) {
    const label = window.prompt('Rename memory block', currentLabel);
    if (label == null) return;
    const trimmed = label.trim();
    if (!trimmed) return;
    const res = await this.api.mutate(`/user/memories/${encodeURIComponent(blockId)}`, {
      method: 'PATCH', body: { label: trimmed },
    });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Rename failed.', 'error'); return; }
    this._notify('Memory renamed.', 'success');
    await this._reloadMemories();
  }

  async _deleteMemory(blockId, label) {
    if (!window.confirm(`Delete memory block "${label}"? It is removed from all agents.`)) return;
    const res = await this.api.mutate(`/user/memories/${encodeURIComponent(blockId)}`, { method: 'DELETE' });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Delete failed.', 'error'); return; }
    this._notify('Memory deleted.', 'success');
    const next = new Set(this._agentMemIds); next.delete(blockId); this._agentMemIds = next;
    await this._reloadMemories();
  }

  async _toggleAttach(blockId) {
    if (!this._selectedId) return;
    const attached = this._agentMemIds.has(blockId);
    const path = `/user/agents/${encodeURIComponent(this._selectedId)}/memories/${encodeURIComponent(blockId)}`;
    const res = await this.api.mutate(path, { method: attached ? 'DELETE' : 'POST' });
    if (!res.ok) { this._notify(res.error ? res.error.message : 'Update failed.', 'error'); return; }
    const next = new Set(this._agentMemIds);
    if (attached) next.delete(blockId); else next.add(blockId);
    this._agentMemIds = next;
    this._notify(attached ? 'Memory detached.' : 'Memory attached to agent.', 'success');
  }

  async _reloadMemories() {
    const memories = await this.api.get('/user/memories');
    this._memories = (memories && Array.isArray(memories.memories)) ? memories.memories : [];
  }

  // ── render: agent list rail ────────────────────────────────
  _renderList() {
    return html`
      <div class="ys-builder-col">
        <div>
          <div class="ys-builder-h">Your agents</div>
          <button class="ys-btn ys-newagent" @click=${() => this._startCreate()}>+ New agent</button>
        </div>
        <div class="ys-ablist">
          ${this._agents.length === 0
            ? html`<div class="ys-txt-note">No agents yet. Create one to begin.</div>`
            : this._agents.map((a) => html`
                <div class="ys-ablist-item ${a.ua_id === this._selectedId ? 'ys-ablist-active' : ''}"
                     role="button" tabindex="0" data-ua=${a.ua_id}
                     @click=${() => this._select(a.ua_id)}
                     @keydown=${(e) => { if (e.key === 'Enter') this._select(a.ua_id); }}>
                  <div class="ys-ablist-name">${a.name}</div>
                  <div class="ys-ablist-meta">${(a.effective_skills || []).length} skill(s)${a.description ? ` · ${a.description}` : ''}</div>
                </div>`)}
        </div>
      </div>`;
  }

  // ── render: create form ────────────────────────────────────
  _renderCreate() {
    return html`
      <div class="ys-card ys-create-panel">
        <div class="ys-builder-h">Create an agent</div>
        <div class="ys-builder-sub">Name it, give it a personality, and pick skills within your ceiling.</div>
        <div class="ys-form-row">
          <label class="ys-label">Name</label>
          <input id="ys-new-name" class="ys-input" maxlength="128" placeholder="e.g. Research assistant">
        </div>
        <div class="ys-form-row">
          <label class="ys-label">Description</label>
          <input id="ys-new-desc" class="ys-input" maxlength="512" placeholder="Optional short description">
        </div>
        <div class="ys-form-row">
          <label class="ys-label">Persona (Letta)</label>
          <textarea id="ys-new-persona" class="ys-textarea" rows="3"
                    placeholder="I am a helpful AI assistant with persistent memory."></textarea>
        </div>
        <div class="ys-form-row">
          <label class="ys-label">System prompt</label>
          <textarea id="ys-new-sysprompt" class="ys-textarea" rows="3"
                    placeholder="Optional system instructions"></textarea>
        </div>
        <div class="ys-form-row">
          <label class="ys-label">Skills</label>
          ${this._renderSkillChips()}
        </div>
        <div class="ys-form-actions">
          <button class="ys-btn ys-create-submit" ?disabled=${this._busy} @click=${() => this._createAgent()}>Create agent</button>
          <button class="ys-btn ys-btn-secondary" @click=${() => { this._creating = false; }}>Cancel</button>
        </div>
      </div>`;
  }

  _renderSkillChips() {
    if (!this._skills.length) {
      return html`<div class="ys-txt-note">No skills available within your ceiling.</div>`;
    }
    return html`
      <div class="ys-skill-grid">
        ${this._skills.map((s) => {
          const on = this._declared.has(s);
          return html`
            <label class="ys-skill-chip ${on ? 'ys-skill-on' : ''}" data-skill=${s}>
              <input type="checkbox" .checked=${on} @change=${() => this._toggleSkill(s)}>
              <span>${s}</span>
            </label>`;
        })}
      </div>`;
  }

  // ── render: editor ─────────────────────────────────────────
  _renderEditor() {
    const a = this._selected;
    return html`
      <div class="ys-builder-col">
        <div class="ys-card">
          <div class="ys-builder-h">${a.name}</div>
          <div class="ys-form-row">
            <label class="ys-label">Name</label>
            <input id="ys-edit-name" class="ys-input" maxlength="128">
          </div>
          <div class="ys-form-row">
            <label class="ys-label">Description</label>
            <input id="ys-edit-desc" class="ys-input" maxlength="512">
          </div>
          <div class="ys-form-actions">
            <button class="ys-btn ys-save-basics" ?disabled=${this._busy} @click=${() => this._saveBasics()}>Save</button>
            <button class="ys-btn ys-btn-danger ys-delete-agent" ?disabled=${this._busy} @click=${() => this._deleteAgent()}>Delete agent</button>
          </div>
        </div>

        <div class="ys-card">
          <div class="ys-builder-h">Personality</div>
          <div class="ys-form-row">
            <label class="ys-label">Persona</label>
            <textarea id="ys-edit-persona" class="ys-textarea" rows="4"></textarea>
          </div>
          <div class="ys-form-row">
            <label class="ys-label">System prompt</label>
            <textarea id="ys-edit-sysprompt" class="ys-textarea" rows="4"></textarea>
          </div>
          <div class="ys-form-actions">
            <button class="ys-btn ys-save-personality" ?disabled=${this._busy} @click=${() => this._savePersonality()}>Save personality</button>
          </div>
        </div>

        <div class="ys-card">
          <div class="ys-builder-h">Skills</div>
          <div class="ys-builder-sub">Only skills within your ceiling are shown. Rejected skills are dropped server-side.</div>
          ${this._renderSkillChips()}
          ${this._rejected.length
            ? html`<div class="ys-txt-note">Rejected (outside your ceiling): ${this._rejected.join(', ')}</div>`
            : nothing}
          <div class="ys-form-actions">
            <button class="ys-btn ys-save-skills" ?disabled=${this._busy} @click=${() => this._saveSkills()}>Save skills</button>
          </div>
        </div>

        <div class="ys-card">
          <div class="ys-builder-h">Task memories</div>
          <div class="ys-builder-sub">Attach one or more memory blocks for different tasks. Attached blocks travel with this agent into chat.</div>
          ${this._memories.length === 0
            ? html`<div class="ys-txt-note">No memory blocks yet. Create one below.</div>`
            : this._memories.map((m) => {
                const on = this._agentMemIds.has(m.block_id);
                return html`
                  <div class="ys-mem-row" data-block=${m.block_id}>
                    <label class="ys-skill-chip ${on ? 'ys-skill-on' : ''} ys-mem-attach">
                      <input type="checkbox" .checked=${on} @change=${() => this._toggleAttach(m.block_id)}>
                      <span class="ys-mem-label">${m.label}</span>
                    </label>
                    <button class="ys-btn ys-btn-ghost ys-mem-rename" @click=${() => this._renameMemory(m.block_id, m.label)}>Rename</button>
                    <button class="ys-btn ys-btn-ghost ys-mem-delete" @click=${() => this._deleteMemory(m.block_id, m.label)}>Delete</button>
                  </div>`;
              })}
          <div class="ys-form-row">
            <label class="ys-label">New memory block</label>
            <input id="ys-mem-new-label" class="ys-input" maxlength="128" placeholder="Label (e.g. project-acme)">
            <textarea id="ys-mem-new-value" class="ys-textarea" rows="2" placeholder="Initial memory value (optional)"></textarea>
          </div>
          <div class="ys-form-actions">
            <button class="ys-btn ys-mem-create" @click=${() => this._createMemory()}>Create memory</button>
          </div>
        </div>
      </div>`;
  }

  _renderRight() {
    if (this._creating) return this._renderCreate();
    if (this._selected) return this._renderEditor();
    return html`<div class="ys-card"><div class="ys-txt-note">Select an agent on the left, or create a new one.</div></div>`;
  }

  render() {
    return html`
      <div class="ys-app">
        <ys-session-header .username=${this._username} active="agents"></ys-session-header>
        <div class="ys-builder-wrap">
          <div class="ys-builder-grid">
            ${this._renderList()}
            ${this._renderRight()}
          </div>
        </div>
      </div>`;
  }
}

customElements.define('ys-agent-manager-app', YsAgentManagerApp);
