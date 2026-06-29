// Yashigani 4.0 user app — <ys-settings-panel> (preferences).
//
// TRUSTED-CHROME. A modal preferences panel (default model + light/dark theme).
// All content is system-authored and rendered via Lit auto-escaping; model ids
// are identifiers (textContent), never markdown. No fetch here — preferences are
// client-local (localStorage, owned by the root app); this component only emits
// the chosen values upward via `ys-prefs-change`. Reuses the shared <ys-modal>
// chrome so the overlay/focus behaviour matches the rest of the layer.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import '/static/ui4/core/widgets/ys-modal.js';

export class YsSettingsPanel extends LitElement {
  static properties = {
    open: { type: Boolean, reflect: true },
    models: { type: Array },
    defaultModel: { type: String },
    theme: { type: String },
    _draftModel: { state: true },
    _draftTheme: { state: true },
  };

  constructor() {
    super();
    this.open = false;
    this.models = [];
    this.defaultModel = '';
    this.theme = 'light';
    this._draftModel = '';
    this._draftTheme = 'light';
  }

  createRenderRoot() { return this; }

  willUpdate(changed) {
    // Seed the draft from the live prefs each time the panel is (re)opened.
    if (changed.has('open') && this.open) {
      this._draftModel = this.defaultModel || '';
      this._draftTheme = this.theme || 'light';
    }
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

  render() {
    if (!this.open) return nothing;
    const models = Array.isArray(this.models) ? this.models : [];
    return html`
      <ys-modal .open=${true} heading="Preferences" @ys-close=${() => this._close()}>
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

        <button slot="footer" class="ys-btn ys-btn-secondary"
                @click=${() => this._close()}>Cancel</button>
        <button slot="footer" class="ys-btn ys-settings-save"
                @click=${() => this._save()}>Save</button>
      </ys-modal>`;
  }
}

customElements.define('ys-settings-panel', YsSettingsPanel);
