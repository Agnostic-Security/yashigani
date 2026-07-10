// Yashigani 4.0 shared layer — <ys-form> (spec §5, TRUSTED-CHROME).
//
// Declarative form + validation. Generalises 3.0 fillSelect() (the *good*
// DOM-based pattern, dashboard.js:14-34). Fields render via Lit auto-escape;
// options bound via templates (no innerHTML). Emits `ys-submit` with the values.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsForm extends LitElement {
  static properties = {
    // fields: [{name,label,type?,required?,options?:[{value,label}],placeholder?}]
    fields: { type: Array },
    submitLabel: { type: String },
    _errors: { state: true },
    _values: { state: true },
  };

  constructor() {
    super();
    this.fields = [];
    this.submitLabel = 'Submit';
    this._errors = {};
    this._values = {};
  }

  createRenderRoot() { return this; }

  _set(name, value) {
    this._values = { ...this._values, [name]: value };
  }

  _validate() {
    const errs = {};
    for (const f of this.fields || []) {
      const v = this._values[f.name];
      if (f.required && (v == null || String(v).trim() === '')) {
        errs[f.name] = `${f.label || f.name} is required.`;
      }
    }
    this._errors = errs;
    return Object.keys(errs).length === 0;
  }

  _submit(e) {
    e.preventDefault();
    if (!this._validate()) return;
    this.dispatchEvent(new CustomEvent('ys-submit', { detail: { ...this._values } }));
  }

  /** Programmatic reset (e.g. after a successful mutate). */
  reset() { this._values = {}; this._errors = {}; }

  _renderField(f) {
    const val = this._values[f.name] ?? '';
    const err = this._errors[f.name];
    let control;
    if (f.type === 'select') {
      control = html`
        <select class="ys-select" .value=${val}
                @change=${(e) => this._set(f.name, e.target.value)}>
          <option value="">— select —</option>
          ${(f.options || []).map((o) => html`<option value=${o.value}>${o.label}</option>`)}
        </select>`;
    } else if (f.type === 'textarea') {
      control = html`<textarea class="ys-textarea" placeholder=${f.placeholder || ''}
                     .value=${val} @input=${(e) => this._set(f.name, e.target.value)}></textarea>`;
    } else {
      control = html`<input class="ys-input" type=${f.type || 'text'}
                     placeholder=${f.placeholder || ''} .value=${val}
                     @input=${(e) => this._set(f.name, e.target.value)}>`;
    }
    return html`
      <div class="ys-field">
        ${f.label ? html`<label class="ys-label">${f.label}</label>` : nothing}
        ${control}
        ${err ? html`<div class="ys-field-error">${err}</div>` : nothing}
      </div>`;
  }

  render() {
    return html`
      <form @submit=${(e) => this._submit(e)}>
        ${(this.fields || []).map((f) => this._renderField(f))}
        <button class="ys-btn" type="submit">${this.submitLabel}</button>
      </form>`;
  }
}

customElements.define('ys-form', YsForm);
