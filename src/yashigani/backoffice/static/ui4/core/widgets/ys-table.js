// Yashigani 4.0 shared layer — <ys-table> (spec §5, TRUSTED-CHROME).
//
// Sortable/paged table. Replaces the ~215 innerHTML table-row concats in 3.0
// dashboard.js: rows are bound via Lit, cells via ${value} auto-escape
// (textContent) — escapeHtml() becomes unnecessary because there is no string
// concatenation into a DOM sink anywhere here.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsTable extends LitElement {
  static properties = {
    // columns: [{key, label, sortable?, render?(row)->string}]
    columns: { type: Array },
    rows: { type: Array },
    pageSize: { type: Number },
    _page: { state: true },
    _sortKey: { state: true },
    _sortDir: { state: true },
    emptyText: { type: String },
  };

  constructor() {
    super();
    this.columns = [];
    this.rows = [];
    this.pageSize = 25;
    this._page = 0;
    this._sortKey = null;
    this._sortDir = 1;
    this.emptyText = 'No data.';
  }

  createRenderRoot() { return this; }

  _toggleSort(col) {
    if (!col.sortable) return;
    if (this._sortKey === col.key) this._sortDir = -this._sortDir;
    else { this._sortKey = col.key; this._sortDir = 1; }
    this._page = 0;
  }

  _sorted() {
    const rows = [...(this.rows || [])];
    if (this._sortKey) {
      rows.sort((a, b) => {
        const av = a[this._sortKey]; const bv = b[this._sortKey];
        if (av === bv) return 0;
        return (av > bv ? 1 : -1) * this._sortDir;
      });
    }
    return rows;
  }

  /** Cell value resolver — always returns a STRING bound via Lit auto-escape. */
  _cell(col, row) {
    if (typeof col.render === 'function') return String(col.render(row) ?? '');
    const v = row[col.key];
    return v == null ? '' : String(v);
  }

  render() {
    const cols = this.columns || [];
    const sorted = this._sorted();
    const total = sorted.length;
    const pages = Math.max(1, Math.ceil(total / this.pageSize));
    const page = Math.min(this._page, pages - 1);
    const slice = sorted.slice(page * this.pageSize, page * this.pageSize + this.pageSize);

    return html`
      <table class="ys-table">
        <thead>
          <tr>
            ${cols.map((c) => html`
              <th @click=${() => this._toggleSort(c)}>
                ${c.label}${this._sortKey === c.key ? (this._sortDir === 1 ? ' ▲' : ' ▼') : ''}
              </th>`)}
          </tr>
        </thead>
        <tbody>
          ${slice.length === 0
            ? html`<tr><td class="ys-table-empty" colspan=${cols.length}>${this.emptyText}</td></tr>`
            : slice.map((row) => html`
                <tr>${cols.map((c) => html`<td>${this._cell(c, row)}</td>`)}</tr>`)}
        </tbody>
      </table>
      ${pages > 1 ? html`
        <div class="ys-table-pager">
          <button class="ys-btn ys-btn-ghost" ?disabled=${page === 0}
                  @click=${() => { this._page = page - 1; }}>Prev</button>
          <span>Page ${page + 1} / ${pages} (${total})</span>
          <button class="ys-btn ys-btn-ghost" ?disabled=${page >= pages - 1}
                  @click=${() => { this._page = page + 1; }}>Next</button>
        </div>` : nothing}`;
  }
}

customElements.define('ys-table', YsTable);
