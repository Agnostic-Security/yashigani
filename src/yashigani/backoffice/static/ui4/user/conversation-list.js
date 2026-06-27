// Yashigani 4.0 user app — <ys-conversation-list> (history sidebar).
//
// TRUSTED-CHROME. Renders the user's past conversations + a "New chat" action,
// and the per-conversation rename / delete affordances (the OWUI-parity history
// rail). Data arrives already-typed from the root app via the shared ApiClient
// (sessionKind:'user'); this component performs NO fetch — it dispatches intent
// events upward (the app owns the list as the single source of truth) so there
// is exactly one place that mutates server state.
//
// Conversation titles are server/user-authored IDENTIFIERS, never markdown: they
// reach the DOM only through Lit auto-escaping (textContent), never the §3
// markdown sink (spec §3.3). Inline rename uses a plain <input> bound to local
// state; nothing here ever touches innerHTML.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsConversationList extends LitElement {
  static properties = {
    conversations: { type: Array },
    activeId: { type: String },
    busy: { type: Boolean },
    _renamingId: { state: true },
    _renameValue: { state: true },
    _confirmDeleteId: { state: true },
  };

  constructor() {
    super();
    this.conversations = [];
    this.activeId = '';
    this.busy = false;
    this._renamingId = '';
    this._renameValue = '';
    this._confirmDeleteId = '';
  }

  createRenderRoot() { return this; }

  static _id(c) { return String(c.id ?? c.conversation_id ?? c.uuid ?? ''); }
  static _title(c) {
    const t = c.title ?? c.name ?? '';
    return (typeof t === 'string' && t.trim()) ? t : 'Untitled chat';
  }

  _emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }

  _new() {
    if (this.busy) return;
    this._cancelRename();
    this._confirmDeleteId = '';
    this._emit('ys-conversation-new', {});
  }

  _select(c) {
    if (this._renamingId) return; // don't navigate while editing
    this._emit('ys-conversation-select', { id: YsConversationList._id(c) });
  }

  _startRename(c, e) {
    if (e) e.stopPropagation();
    this._confirmDeleteId = '';
    this._renamingId = YsConversationList._id(c);
    this._renameValue = YsConversationList._title(c);
  }

  _cancelRename() {
    this._renamingId = '';
    this._renameValue = '';
  }

  _commitRename(e) {
    if (e) e.stopPropagation();
    const id = this._renamingId;
    const title = (this._renameValue || '').trim();
    this._cancelRename();
    if (id && title) this._emit('ys-conversation-rename', { id, title });
  }

  _onRenameKey(e) {
    if (e.key === 'Enter') { e.preventDefault(); this._commitRename(e); }
    else if (e.key === 'Escape') { e.preventDefault(); this._cancelRename(); }
  }

  _askDelete(c, e) {
    if (e) e.stopPropagation();
    this._cancelRename();
    this._confirmDeleteId = YsConversationList._id(c);
  }

  _cancelDelete(e) {
    if (e) e.stopPropagation();
    this._confirmDeleteId = '';
  }

  _confirmDelete(e) {
    if (e) e.stopPropagation();
    const id = this._confirmDeleteId;
    this._confirmDeleteId = '';
    if (id) this._emit('ys-conversation-delete', { id });
  }

  _renderItem(c) {
    const id = YsConversationList._id(c);
    const title = YsConversationList._title(c);
    const active = id && id === this.activeId;

    if (id && id === this._renamingId) {
      return html`
        <div class="ys-conv ys-conv-editing">
          <input class="ys-input ys-conv-rename" .value=${this._renameValue}
                 aria-label="Rename conversation"
                 @input=${(e) => { this._renameValue = e.target.value; }}
                 @keydown=${(e) => this._onRenameKey(e)}
                 @click=${(e) => e.stopPropagation()}>
          <div class="ys-conv-actions">
            <button class="ys-btn ys-btn-ghost ys-conv-act" title="Save"
                    @click=${(e) => this._commitRename(e)}>Save</button>
            <button class="ys-btn ys-btn-ghost ys-conv-act" title="Cancel"
                    @click=${(e) => { e.stopPropagation(); this._cancelRename(); }}>Cancel</button>
          </div>
        </div>`;
    }

    if (id && id === this._confirmDeleteId) {
      return html`
        <div class="ys-conv ys-conv-confirm">
          <span class="ys-conv-title">Delete “${title}”?</span>
          <div class="ys-conv-actions">
            <button class="ys-btn ys-btn-danger ys-conv-act" title="Confirm delete"
                    @click=${(e) => this._confirmDelete(e)}>Delete</button>
            <button class="ys-btn ys-btn-ghost ys-conv-act" title="Cancel"
                    @click=${(e) => this._cancelDelete(e)}>Cancel</button>
          </div>
        </div>`;
    }

    return html`
      <div class="ys-conv ${active ? 'ys-conv-active' : ''}"
           role="button" tabindex="0" data-conv-id=${id}
           @click=${() => this._select(c)}
           @keydown=${(e) => { if (e.key === 'Enter') this._select(c); }}>
        <span class="ys-conv-title">${title}</span>
        <div class="ys-conv-actions">
          <button class="ys-btn ys-btn-ghost ys-conv-act ys-conv-rename-btn" title="Rename"
                  aria-label="Rename conversation"
                  @click=${(e) => this._startRename(c, e)}>Rename</button>
          <button class="ys-btn ys-btn-ghost ys-conv-act ys-conv-delete-btn" title="Delete"
                  aria-label="Delete conversation"
                  @click=${(e) => this._askDelete(c, e)}>Delete</button>
        </div>
      </div>`;
  }

  render() {
    const convs = Array.isArray(this.conversations) ? this.conversations : [];
    return html`
      <div class="ys-section ys-conv-section">
        <div class="ys-conv-head">
          <div class="ys-section-title">Chats</div>
          <button class="ys-btn ys-conv-new" ?disabled=${this.busy}
                  @click=${() => this._new()}>+ New chat</button>
        </div>
        ${convs.length === 0
          ? html`<div class="ys-txt-note">No conversations yet. Start a new chat.</div>`
          : html`<div class="ys-conv-list">${convs.map((c) => this._renderItem(c))}</div>`}
      </div>`;
  }
}

customElements.define('ys-conversation-list', YsConversationList);
