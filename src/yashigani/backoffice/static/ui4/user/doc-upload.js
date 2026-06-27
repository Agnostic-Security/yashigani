// Yashigani 4.0 user app — <ys-doc-upload> (doc-OPA file-upload UI).
//
// Uploads a document to POST /user/documents and renders the returned verdict.
// Uses the shared ApiClient.mutate (sessionKind:'user') — NOT a raw fetch — so
// the audited error model, step-up handling, same-origin credentials and the
// X-Yashigani-Plane selector all apply. The file is sent as JSON base64
// (contract seam with Tom: { filename, content_type, content_base64 }).
//
// The verdict is decoded from STRUCTURED response fields via ApiClient.decode()
// and rendered by <ys-verdict-banner> as TRUSTED-CHROME (RISK-105) — never by
// scanning any returned text. Any returned processed/redacted document text is
// UNTRUSTED-CONTENT and goes through <ys-markdown> (the §3 pipeline) only.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import '/static/ui4/core/widgets/ys-verdict-banner.js';
import '/static/ui4/core/widgets/ys-markdown.js';

const ACTION_BADGE = {
  pass: 'ys-badge-green',
  allow: 'ys-badge-green',
  log: 'ys-badge-blue',
  redact: 'ys-badge-amber',
  pseudonymize: 'ys-badge-amber',
  pseudonymise: 'ys-badge-amber',
  block: 'ys-badge-red',
};

export class YsDocUpload extends LitElement {
  static properties = {
    api: { attribute: false },
    _busy: { state: true },
    _verdict: { state: true },
    _action: { state: true },
    _processed: { state: true },
    _error: { state: true },
    _filename: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this._busy = false;
    this._verdict = null;
    this._action = '';
    this._processed = '';
    this._error = '';
    this._filename = '';
  }

  createRenderRoot() { return this; }

  _readAsBase64(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onerror = () => reject(new Error('read failed'));
      fr.onload = () => {
        const res = String(fr.result || '');
        const comma = res.indexOf(',');
        resolve(comma >= 0 ? res.slice(comma + 1) : res); // strip data: prefix
      };
      fr.readAsDataURL(file);
    });
  }

  async _onFile(e) {
    const file = e.target && e.target.files && e.target.files[0];
    if (!file || !this.api) return;
    this._busy = true;
    this._verdict = null;
    this._action = '';
    this._processed = '';
    this._error = '';
    this._filename = file.name;
    try {
      const content_base64 = await this._readAsBase64(file);
      const result = await this.api.mutate('/user/documents', {
        method: 'POST',
        body: {
          filename: file.name,
          content_type: file.type || 'application/octet-stream',
          content_base64,
        },
      });
      if (!result.ok) {
        this._error = (result.error && result.error.message) || 'Document check failed.';
        return;
      }
      const data = result.data || {};
      // Verdict from STRUCTURED fields only (RISK-105).
      this._verdict = this.api.decode(data);
      this._action = String(data.action ?? data.verdict ?? '').toLowerCase();
      // Any returned processed/redacted text is UNTRUSTED → ys-markdown only.
      this._processed = data.processed_content ?? data.redacted_content ?? data.content ?? '';
    } catch (err) {
      this._error = 'Document check failed.';
    } finally {
      this._busy = false;
      if (e.target) e.target.value = ''; // allow re-upload of the same file
    }
  }

  render() {
    const badge = ACTION_BADGE[this._action] || 'ys-badge-blue';
    return html`
      <label class="ys-doc-drop">
        ${this._busy
          ? html`Checking ${this._filename}…`
          : html`<span>Drop or choose a document to check</span>`}
        <input type="file" class="ys-hidden" ?disabled=${this._busy}
               @change=${(e) => this._onFile(e)}>
      </label>

      <div class="ys-doc-result">
        ${this._error ? html`<div class="ys-field-error">${this._error}</div>` : nothing}

        ${this._action
          ? html`<div class="ys-doc-action">
              Verdict <span class="ys-badge ${badge}">${this._action}</span>
            </div>`
          : nothing}

        ${this._verdict
          ? html`<ys-verdict-banner .verdict=${this._verdict}></ys-verdict-banner>`
          : nothing}

        ${this._processed
          ? html`<ys-markdown .content=${this._processed}></ys-markdown>`
          : nothing}
      </div>`;
  }
}

customElements.define('ys-doc-upload', YsDocUpload);
