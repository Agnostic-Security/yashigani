// Yashigani 4.0 user app — <ys-settings-panel> (preferences + API keys).
//
// TRUSTED-CHROME. A modal preferences panel (default model + light/dark theme,
// client-local) plus the self-service API-key surface (V50-027 — the backend
// /me/api-key / /me/api-keys routes had no UI anywhere in ui4). The API-key
// section owns its own reads/writes through the shared ApiClient
// (sessionKind:'user') passed down from ys-user-app, the same way ys-user-sidebar
// hands .api to <ys-doc-upload> — this component does NOT construct its own
// client (RISK-100: one ApiClient instance per plane). Mutations go through
// ApiClient.mutate(), which already carries the fixed step-up flow (V50-023 —
// posts { totp_code } to /auth/stepup on a step_up_required 401 and retries
// once); this component never talks to /auth/stepup directly. All content is
// system-authored and rendered via Lit auto-escaping; model ids, key ids and
// the issued token are identifiers/secrets (textContent), never markdown.
// Reuses the shared <ys-modal> chrome so the overlay/focus behaviour matches
// the rest of the layer.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import '/static/ui4/core/widgets/ys-modal.js';
import { copyText } from '/static/ui4/core/clipboard.js';

export class YsSettingsPanel extends LitElement {
  static properties = {
    open: { type: Boolean, reflect: true },
    models: { type: Array },
    defaultModel: { type: String },
    theme: { type: String },
    // shared ApiClient (sessionKind:'user') — owns the /me/api-key* reads/writes.
    api: { attribute: false },
    _draftModel: { state: true },
    _draftTheme: { state: true },
    _apiKeys: { state: true },
    _keysLoading: { state: true },
    _keysError: { state: true },
    _revokeBusyId: { state: true },
    _issueBusy: { state: true },
    _issueError: { state: true },
    _issuedToken: { state: true },
    _copyLabel: { state: true },
  };

  constructor() {
    super();
    this.open = false;
    this.models = [];
    this.defaultModel = '';
    this.theme = 'light';
    this.api = null;
    this._draftModel = '';
    this._draftTheme = 'light';
    this._apiKeys = [];
    this._keysLoading = false;
    this._keysError = '';
    this._revokeBusyId = '';
    this._issueBusy = false;
    this._issueError = '';
    this._issuedToken = null;
    this._copyLabel = 'Copy';
  }

  createRenderRoot() { return this; }

  willUpdate(changed) {
    // Seed the draft from the live prefs each time the panel is (re)opened, and
    // load the key list fresh. The just-issued plaintext token is shown_once —
    // it is cleared on every (re)open so a stale secret never lingers on screen.
    if (changed.has('open') && this.open) {
      this._draftModel = this.defaultModel || '';
      this._draftTheme = this.theme || 'light';
      this._issuedToken = null;
      this._issueError = '';
      this._keysError = '';
      this._loadKeys();
    }
  }

  // ── API keys (/me/api-key, /me/api-keys) ───────────────────
  async _loadKeys() {
    if (!this.api) return;
    this._keysLoading = true;
    const data = await this.api.get('/me/api-keys');
    this._keysLoading = false;
    if (data === null) {
      // ApiClient.get() returns null on any non-OK/network error (and already
      // redirected to /login on a 401) — surface it rather than silently
      // showing an empty list as if the user has no keys.
      this._keysError = 'Could not load API keys.';
      this._apiKeys = [];
      return;
    }
    this._apiKeys = Array.isArray(data.api_keys) ? data.api_keys : [];
  }

  async _issueKey() {
    if (!this.api || this._issueBusy) return;
    this._issueBusy = true;
    this._issueError = '';
    const res = await this.api.mutate('/me/api-key', { method: 'POST' });
    this._issueBusy = false;
    if (!res.ok) {
      // step_up_cancelled = the user closed the TOTP prompt — not an error.
      if (res.error && res.error.code !== 'step_up_cancelled') {
        this._issueError = res.error.message || 'Could not issue API key.';
      }
      return;
    }
    const data = res.data || {};
    this._issuedToken = {
      plaintext_token: String(data.plaintext_token ?? ''),
      expires_at: String(data.expires_at ?? ''),
      shown_once: data.shown_once !== false,
    };
    this._copyLabel = 'Copy';
    await this._loadKeys();
  }

  async _revokeKey(keyId) {
    if (!this.api || this._revokeBusyId) return;
    if (!window.confirm('Revoke this API key? Anything using it will stop working immediately.')) return;
    this._revokeBusyId = keyId;
    this._keysError = '';
    const res = await this.api.mutate(`/me/api-keys/${encodeURIComponent(keyId)}`, { method: 'DELETE' });
    this._revokeBusyId = '';
    if (!res.ok) {
      if (res.error && res.error.code !== 'step_up_cancelled') {
        this._keysError = res.error.message || 'Could not revoke API key.';
      }
      return;
    }
    // The revoked key can no longer be the one on screen as a shown-once reveal.
    if (this._issuedToken) this._issuedToken = null;
    await this._loadKeys();
  }

  async _copyToken() {
    const tok = this._issuedToken && this._issuedToken.plaintext_token;
    if (!tok) return;
    const ok = await copyText(tok);
    this._copyLabel = ok ? 'Copied' : 'Copy failed';
    setTimeout(() => { this._copyLabel = 'Copy'; }, 1500);
  }

  static _id(m) { return String(m.id ?? m.model ?? m.name ?? ''); }
  static _label(m) { return String(m.name ?? m.id ?? m.model ?? ''); }

  _close() {
    this.open = false;
    this.dispatchEvent(new CustomEvent('ys-close', { bubbles: true, composed: true }));
  }

  _save() {
    this.dispatchEvent(new CustomEvent('ys-prefs-change', {
      detail: { defaultModel: this._draftModel || '', theme: this._draftTheme || 'light' },
      bubbles: true,
      composed: true,
    }));
    this.open = false;
  }

  // ── render: API keys section ────────────────────────────────
  _renderApiKeys() {
    const keys = Array.isArray(this._apiKeys) ? this._apiKeys : [];
    return html`
      <div class="ys-field ys-apikeys-section">
        <label class="ys-label">API keys</label>
        <div class="ys-txt-note">
          Use an API key to call the Yashigani API directly from scripts or agents.
        </div>

        ${this._keysError ? html`<div class="ys-field-error">${this._keysError}</div>` : nothing}

        ${this._keysLoading
          ? html`<div class="ys-txt-note">Loading…</div>`
          : (keys.length === 0
              ? html`<div class="ys-txt-note">No API keys issued yet.</div>`
              : html`<div class="ys-apikey-list">
                  ${keys.map((k) => {
                    const id = String(k.key_id ?? '');
                    const busy = this._revokeBusyId === id;
                    return html`
                      <div class="ys-apikey-row" data-key-id=${id}>
                        <div class="ys-apikey-meta">
                          <span class="ys-apikey-last4">•••• ${k.last4 ?? '****'}</span>
                          <span class="ys-txt-note">
                            ${k.created_at ? `issued ${k.created_at}` : nothing}
                            ${k.expires_at ? ` · expires ${k.expires_at}` : nothing}
                          </span>
                        </div>
                        <button class="ys-btn ys-btn-danger ys-apikey-revoke"
                                ?disabled=${busy || !!this._revokeBusyId}
                                @click=${() => this._revokeKey(id)}>
                          ${busy ? 'Revoking…' : 'Revoke'}
                        </button>
                      </div>`;
                  })}
                </div>`)}

        <button class="ys-btn ys-btn-secondary ys-apikey-issue"
                ?disabled=${this._issueBusy}
                @click=${() => this._issueKey()}>
          ${this._issueBusy ? 'Issuing…' : (keys.length ? 'Rotate API key' : 'Create API key')}
        </button>

        ${this._issueError ? html`<div class="ys-field-error">${this._issueError}</div>` : nothing}

        ${this._issuedToken ? this._renderIssuedToken() : nothing}
      </div>`;
  }

  _renderIssuedToken() {
    const tok = this._issuedToken;
    return html`
      <div class="ys-apikey-reveal">
        <div class="ys-badge ys-badge-amber">Shown once — copy it now</div>
        <div class="ys-apikey-token-row">
          <code class="ys-apikey-token">${tok.plaintext_token}</code>
          <button class="ys-btn ys-btn-secondary ys-apikey-copy"
                  @click=${() => this._copyToken()}>${this._copyLabel}</button>
        </div>
        ${tok.expires_at ? html`<div class="ys-txt-note">Expires ${tok.expires_at}</div>` : nothing}
        <div class="ys-txt-note">This token will not be shown again. Store it securely.</div>
      </div>`;
  }

  render() {
    if (!this.open) return nothing;
    const models = Array.isArray(this.models) ? this.models : [];
    return html`
      <ys-modal .open=${true} heading="Preferences & API keys" @ys-close=${() => this._close()}>
        <div class="ys-field">
          <label class="ys-label" for="ys-pref-model">Default model / agent</label>
          <select id="ys-pref-model" class="ys-select"
                  @change=${(e) => { this._draftModel = e.target.value; }}>
            <option value="" ?selected=${!this._draftModel}>— Last used —</option>
            ${models.map((m) => {
              const id = YsSettingsPanel._id(m);
              return html`<option value=${id} ?selected=${id === this._draftModel}>
                ${YsSettingsPanel._label(m)}</option>`;
            })}
          </select>
        </div>

        <div class="ys-field">
          <label class="ys-label" for="ys-pref-theme">Theme</label>
          <select id="ys-pref-theme" class="ys-select"
                  @change=${(e) => { this._draftTheme = e.target.value; }}>
            <option value="light" ?selected=${this._draftTheme !== 'dark'}>Light</option>
            <option value="dark" ?selected=${this._draftTheme === 'dark'}>Dark</option>
          </select>
        </div>

        ${this._renderApiKeys()}

        <button slot="footer" class="ys-btn ys-btn-secondary"
                @click=${() => this._close()}>Cancel</button>
        <button slot="footer" class="ys-btn ys-settings-save"
                @click=${() => this._save()}>Save</button>
      </ys-modal>`;
  }
}

customElements.define('ys-settings-panel', YsSettingsPanel);
