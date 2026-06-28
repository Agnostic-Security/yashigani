// Yashigani 4.0 admin shell — Crypto & Integrity module ("Ops & Crypto" group).
//
// Bundles the crypto/attestation + deploy-integrity surfaces:
//   GET /admin/crypto/inventory            → algorithm inventory + FIPS attestation (CI-01)
//   GET /admin/version                     → deploy/version status, now 4.0.0 (VE-01, NEW)
//   GET /admin/manifest-registrations      → manifest registration ledger (GAP MH-01/02)
//   GET /admin/manifest-registrations/{id} → full record incl. YAML blob
//   (manifest ceremony = CLI-only via yashigani-manifest.py — surfaced, not faked)
//   Vendored-asset / SRI integrity status  → NEW client-side check of the loaded
//                                            vendor bundle + Trusted-Types enforcement
//   CSP-report viewer (/admin/csp-report)  → NEW; the endpoint is POST-only/log-only,
//                                            so this explains the sink + where reports land
//
// TRUSTED-CHROME: algorithm names, version strings, manifest hashes are all
// server-authored and rendered via Lit auto-escape — no §3 markdown sink. All
// reads only; the one mutating manifest op (ceremony) is CLI/SPIFFE-signed and is
// intentionally not exposed in-console (parallels the agent-token-rotate non-gap).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
// (registerAdminModule no longer imported — Crypto is embedded under PKI, not a nav entry.)

void widgets;

// Vendored assets the hardened UI depends on — checked for presence (integrity).
const VENDOR_ASSETS = [
  '/static/vendor/lit/lit-core.min.js',
];

export class YsAdminCryptoInventory extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _inventory: { state: true },
    _version: { state: true },
    _manifests: { state: true },
    _manifestDetail: { state: true },
    _assets: { state: true },     // [{url, ok}]
    _ttActive: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._inventory = null;
    this._version = null;
    this._manifests = null;
    this._manifestDetail = null;
    this._assets = [];
    this._ttActive = false;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [inv, ver, manifests] = await Promise.all([
      this.api.get('/admin/crypto/inventory'),
      this.api.get('/admin/version'),
      this.api.get('/admin/manifest-registrations'),
    ]);
    this._inventory = inv || null;
    this._version = ver || null;
    this._manifests = manifests || null;
    this._loading = false;
    this._checkIntegrity();
  }

  _toast(msg, kind) { if (this.app && this.app.toast) this.app.toast(msg, kind); }

  // ── Vendored-asset / SRI integrity (client-side) ─────────────────────────────
  async _checkIntegrity() {
    // Trusted-Types enforcement is active iff the named policies were registered
    // (admin.html declares: yashigani-render, dompurify, lit-html; no `default`).
    this._ttActive = !!(window.trustedTypes && typeof window.trustedTypes.createPolicy === 'function');
    const results = await Promise.all(VENDOR_ASSETS.map(async (url) => {
      try {
        const r = await fetch(url, { method: 'GET', credentials: 'same-origin' });
        return { url, ok: r.ok, status: r.status };
      } catch {
        return { url, ok: false, status: 0 };
      }
    }));
    this._assets = results;
  }

  // ── Crypto inventory ──────────────────────────────────────────────────────────
  _renderInventory() {
    const inv = this._inventory;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Cryptographic inventory
          ${inv ? html`<span class="ys-badge ${inv.fips_mode_active ? 'ys-badge-green' : 'ys-badge-amber'}">FIPS ${inv.fips_mode_active ? 'active' : 'inactive'}${inv.cmvp_cert ? ` · CMVP ${inv.cmvp_cert}` : ''}</span>` : nothing}
        </div>
        <div class="ys-panel-body">
          ${!inv ? html`<div class="ys-txt-note">Inventory unavailable.</div>` : html`
            <table class="ys-table">
              <thead><tr><th>Algorithm</th><th>Usage</th><th>Strength</th></tr></thead>
              <tbody>${(inv.algorithms || []).map((a) => html`
                <tr><td>${a.name}</td><td>${a.usage}</td><td>${a.strength}</td></tr>`)}</tbody>
            </table>
            <div class="ys-txt-note">
              Post-quantum: ${(inv.post_quantum || []).join('; ') || '—'} ·
              Deprecated: ${(inv.deprecated && inv.deprecated.length) ? inv.deprecated.join('; ') : 'none'} ·
              Compliance: ${inv.compliance || '—'}
            </div>`}
        </div>
      </div>`;
  }

  // ── Deploy / version status ───────────────────────────────────────────────────
  _renderVersion() {
    const v = this._version;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Deploy / version</div>
        <div class="ys-panel-body">
          ${!v ? html`<div class="ys-txt-note">Version unavailable.</div>` : html`
            <div class="ys-stat-grid">
              <div class="ys-stat-card">
                <div class="ys-stat-num ys-stat-num--sm">${v.running_version || '—'}</div>
                <div class="ys-stat-label">Running version</div>
              </div>
              <div class="ys-stat-card">
                <div class="ys-stat-num ys-stat-num--sm">${v.check_skipped ? '—' : (v.latest_version || '—')}</div>
                <div class="ys-stat-label">Latest published</div>
              </div>
            </div>
            ${v.update_available
              ? html`<div class="ys-field-error">Update available (${v.update_type}). ${v.release_url ? `See ${v.release_url}` : ''}</div>`
              : (v.check_skipped
                ? html`<div class="ys-txt-note">${v.skip_reason || 'Version check disabled.'}</div>`
                : html`<div class="ys-txt-note">Running the latest published release.</div>`)}`}
        </div>
      </div>`;
  }

  // ── Manifest registration ledger ──────────────────────────────────────────────
  async _viewManifest(id) {
    this._manifestDetail = null;
    const d = await this.api.get(`/admin/manifest-registrations/${encodeURIComponent(id)}`);
    this._manifestDetail = d || { id, _error: true };
  }

  _renderManifests() {
    const items = (this._manifests && Array.isArray(this._manifests.items)) ? this._manifests.items : [];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Manifest registrations
          ${this._manifests ? html`<span class="ys-badge ys-badge-blue">${this._manifests.total ?? items.length} total</span>` : nothing}
        </div>
        <div class="ys-panel-body">
          ${items.length === 0
            ? html`<div class="ys-txt-note">No manifest registrations recorded.</div>`
            : html`<table class="ys-table">
                <thead><tr><th>ID</th><th>Agent</th><th>SHA-256</th><th>Registered by</th><th>At</th><th></th></tr></thead>
                <tbody>${items.map((m) => html`
                  <tr>
                    <td>${m.id}</td>
                    <td>${m.agent_id}</td>
                    <td><code class="ys-system-chrome-code">${(m.manifest_sha256 || '').slice(0, 16)}…</code></td>
                    <td>${m.registered_by_operator_identity || '—'}</td>
                    <td>${m.registered_at || '—'}</td>
                    <td><button class="ys-btn ys-btn-ghost" @click=${() => this._viewManifest(m.id)}>View</button></td>
                  </tr>`)}</tbody>
              </table>`}
          ${this._renderManifestDetail()}
          <div class="ys-txt-note">
            New registrations / signing ceremonies are recorded by the
            <code class="ys-system-chrome-code">yashigani-manifest.py</code> operator CLI (SPIFFE-signed) —
            not from the console, by design.
          </div>
        </div>
      </div>`;
  }

  _renderManifestDetail() {
    const d = this._manifestDetail;
    if (!d) return nothing;
    if (d._error) return html`<div class="ys-txt-note">Could not load record ${d.id}.</div>`;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Manifest #${d.id}
          <button class="ys-btn ys-btn-ghost" @click=${() => { this._manifestDetail = null; }}>Close</button>
        </div>
        <div class="ys-panel-body">
          <table class="ys-table"><tbody>
            <tr><td>Tenant</td><td>${d.tenant_id || '—'}</td></tr>
            <tr><td>Agent</td><td>${d.agent_id || '—'}</td></tr>
            <tr><td>SHA-256</td><td><code class="ys-system-chrome-code">${d.manifest_sha256 || '—'}</code></td></tr>
            <tr><td>Previous SHA-256</td><td><code class="ys-system-chrome-code">${d.previous_manifest_sha256 || '—'}</code></td></tr>
            <tr><td>Registered by</td><td>${d.registered_by_operator_identity || '—'}</td></tr>
            <tr><td>Registered at</td><td>${d.registered_at || '—'}</td></tr>
          </tbody></table>
          ${d.manifest_yaml_blob
            ? html`<div class="ys-code-wrap"><pre class="ys-system-chrome-code">${d.manifest_yaml_blob}</pre></div>`
            : nothing}
        </div>
      </div>`;
  }

  // ── Vendored-asset / SRI integrity + CSP report ──────────────────────────────
  _renderIntegrity() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Asset integrity &amp; CSP</div>
        <div class="ys-panel-body">
          <ul class="ys-alert-list">
            <li class="ys-alert-item">
              <span class="ys-semaphore ${this._ttActive ? 'ys-semaphore--ok' : 'ys-semaphore--critical'}"></span>
              <span class="ys-alert-label">Trusted-Types enforcement</span>
              <span class="ys-alert-count">${this._ttActive ? 'active' : 'inactive'}</span>
            </li>
            ${this._assets.map((a) => html`
              <li class="ys-alert-item">
                <span class="ys-semaphore ${a.ok ? 'ys-semaphore--ok' : 'ys-semaphore--critical'}"></span>
                <span class="ys-alert-label">${a.url}</span>
                <span class="ys-alert-count">${a.ok ? 'present' : `HTTP ${a.status}`}</span>
              </li>`)}
          </ul>
          <div class="ys-txt-note">
            The strict CSP (no unsafe-inline/eval, require-trusted-types-for 'script') pins the
            vendored bundle to same-origin and fails closed on any DOM-XSS sink. CSP violations are
            POSTed by browsers to <code class="ys-system-chrome-code">/admin/csp-report</code> (log-only,
            no auth) — there is no stored report history to browse; violations surface in the server
            logs / SIEM (Wazuh) feed.
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading crypto & integrity…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <h2 class="ys-admin-section-title">Crypto &amp; Integrity</h2>
        ${this._renderInventory()}
        <div class="ys-admin-2col">
          ${this._renderVersion()}
          ${this._renderIntegrity()}
        </div>
        ${this._renderManifests()}
      </div>`;
  }
}

customElements.define('ys-admin-crypto-inventory', YsAdminCryptoInventory);

// Crypto & Integrity is NO LONGER a standalone nav entry — it is consolidated
// under the PKI module (kms-pki.js renders <ys-admin-crypto-inventory>) per
// Tiago 2026-06-28 ("KMS, PKI and Crypto all under the same — PKI").
// The custom element + its admin-app.js import are retained so PKI can embed it.
