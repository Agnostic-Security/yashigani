// Yashigani 4.0 admin shell — KMS & PKI module ("Ops & Crypto" group).
//
// Rebuilds the 3.0 PKI/Crypto page (static/js/pki.js) on the hardened shell and
// adds the KMS + Vault surfaces the 3.0 SPA never wired (parity-matrix GAPs
// KM-01..07):
//   PKI  GET  /api/v1/admin/pki/status            → per-service cert status
//        GET  /api/v1/admin/pki/chain/{service}   → chain detail
//        POST /api/v1/admin/pki/rotate/{service}  → rotate (STEP-UP)
//        GET  /api/v1/admin/pki/bundle/{service}  → download PEM (read-only)
//   KMS  GET  /admin/kms/status                   → provider + health
//        GET  /admin/kms/schedule                 → rotation schedule
//        POST /admin/kms/schedule                 → set cron (STEP-UP)
//        POST /admin/kms/rotate-now               → manual rotation (STEP-UP)
//        GET  /admin/kms/secrets                  → tracked key NAMES (no values)
//   VAULT GET /admin/kms/vault/status             → Vault health (when provider=Vault)
//        GET  /admin/kms/vault/secrets            → Vault key names
//
// TRUSTED-CHROME: cert metadata, provider names, key names and health strings are
// server-authored and rendered via Lit auto-escape — no §3 markdown sink. The
// dangerous one-click ops (PKI rotate, KMS schedule, KMS rotate-now) are
// StepUpAdminSession server-side: routing them through ctx.api.mutate makes the
// shell's TOTP step-up fire transparently (RISK-103). PKI key material is never
// returned by the API; the bundle download is the public PEM chain only.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

function cleanTs(s) {
  if (!s) return '—';
  return String(s).replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, '');
}

export class YsAdminKmsPki extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _pki: { state: true },          // {ca_mode, services[]}
    _chain: { state: true },        // selected chain detail | null
    _kms: { state: true },          // status
    _schedule: { state: true },
    _kmsSecrets: { state: true },
    _vault: { state: true },        // {status, secrets} | null
    _cronInput: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._pki = null;
    this._chain = null;
    this._kms = null;
    this._schedule = null;
    this._kmsSecrets = null;
    this._vault = null;
    this._cronInput = '';
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [pki, kms, schedule, secrets] = await Promise.all([
      this.api.get('/api/v1/admin/pki/status'),
      this.api.get('/admin/kms/status'),
      this.api.get('/admin/kms/schedule'),
      this.api.get('/admin/kms/secrets'),
    ]);
    this._pki = pki || null;
    this._kms = kms || null;
    this._schedule = schedule || null;
    this._cronInput = (schedule && schedule.cron_expr) || '';
    this._kmsSecrets = secrets || null;
    // Vault detail only when the active provider exposes it (best-effort).
    const vstatus = await this.api.get('/admin/kms/vault/status');
    if (vstatus) {
      const vsecrets = await this.api.get('/admin/kms/vault/secrets');
      this._vault = { status: vstatus, secrets: vsecrets };
    } else {
      this._vault = null;
    }
    this._loading = false;
  }

  _toast(msg, kind) { if (this.app && this.app.toast) this.app.toast(msg, kind); }

  async _mutate(path, opts, okMsg) {
    const res = await this.api.mutate(path, opts);
    if (res.ok) { this._toast(okMsg, 'success'); await this._load(); }
    else this._toast((res.error && res.error.message) || 'Request failed.', 'error');
    return res;
  }

  // ── PKI ──────────────────────────────────────────────────────────────────────
  async _viewChain(service) {
    this._chain = null;
    const data = await this.api.get(`/api/v1/admin/pki/chain/${encodeURIComponent(service)}`);
    this._chain = data || { service, _error: true };
  }

  _rotateCert(service) {
    // STEP-UP gated server-side (StepUpAdminSession). Confirm the disruptive op.
    if (!window.confirm(`Rotate the certificate for "${service}"? Active connections may briefly re-handshake.`)) return;
    this._mutate(`/api/v1/admin/pki/rotate/${encodeURIComponent(service)}`, { method: 'POST' },
      `Rotation requested for ${service}.`);
  }

  async _downloadBundle(service) {
    // Read-only PEM chain (no step-up). Direct fetch → blob → anchor download.
    try {
      const resp = await fetch(`/api/v1/admin/pki/bundle/${encodeURIComponent(service)}`, {
        credentials: 'same-origin', headers: { 'X-Yashigani-Plane': 'admin' },
      });
      if (!resp.ok) { this._toast(`Bundle download failed (HTTP ${resp.status}).`, 'error'); return; }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${service}_cert_bundle.pem`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      this._toast('Bundle download error.', 'error');
    }
  }

  _pkiServiceRows() {
    return (this._pki && Array.isArray(this._pki.services)) ? this._pki.services : [];
  }

  _renderPki() {
    const rows = this._pkiServiceRows();
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          PKI — service certificates
          ${this._pki ? html`<span class="ys-badge ys-badge-blue">CA: ${this._pki.ca_mode || 'internal'}</span>` : nothing}
        </div>
        <div class="ys-panel-body">
          ${rows.length === 0
            ? html`<div class="ys-txt-note">No services in the certificate manifest.</div>`
            : html`<table class="ys-table">
                <thead><tr><th>Service</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
                <tbody>
                  ${rows.map((s) => html`
                    <tr>
                      <td>${s.service}</td>
                      <td>${s.error
                        ? html`<span class="ys-badge ys-badge-red">error</span>`
                        : (s.needs_renewal
                          ? html`<span class="ys-badge ys-badge-amber">renewal needed</span>`
                          : html`<span class="ys-badge ys-badge-green">ok</span>`)}</td>
                      <td>${cleanTs(s.not_after)}</td>
                      <td>
                        <button class="ys-btn ys-btn-ghost" @click=${() => this._viewChain(s.service)}>View</button>
                        <button class="ys-btn ys-btn-secondary" @click=${() => this._rotateCert(s.service)}>Rotate</button>
                        <button class="ys-btn ys-btn-ghost" @click=${() => this._downloadBundle(s.service)}>Download</button>
                      </td>
                    </tr>`)}
                </tbody>
              </table>`}
          ${this._renderChainDetail()}
        </div>
      </div>`;
  }

  _renderChainDetail() {
    const c = this._chain;
    if (!c) return nothing;
    if (c._error) {
      return html`<div class="ys-txt-note">Could not load chain for ${c.service}.</div>`;
    }
    const rows = [
      ['Subject CN', c.subject_cn], ['Issuer CN', c.issuer_cn], ['Serial', c.serial_hex],
      ['Not before', cleanTs(c.not_before)], ['Not after', cleanTs(c.not_after)],
      ['SHA-256', c.fingerprint_sha256], ['DNS SANs', (c.dns_sans || []).join(', ') || '—'],
      ['URI SANs', (c.uri_sans || []).join(', ') || '—'], ['IP SANs', (c.ip_sans || []).join(', ') || '—'],
      ['CA mode', c.ca_mode], ['Chain depth', String(c.chain_depth ?? 1)],
      ['Needs renewal', c.needs_renewal ? 'yes' : 'no'], ['Last rotated', cleanTs(c.last_rotated_at)],
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Chain — ${c.service || ''}
          <button class="ys-btn ys-btn-ghost" @click=${() => { this._chain = null; }}>Close</button>
        </div>
        <div class="ys-panel-body">
          <table class="ys-table"><tbody>
            ${rows.map((r) => html`<tr><td>${r[0]}</td><td>${r[1] || '—'}</td></tr>`)}
          </tbody></table>
        </div>
      </div>`;
  }

  // ── KMS ──────────────────────────────────────────────────────────────────────
  _saveSchedule() {
    const cron = this._cronInput.trim();
    if (!cron) { this._toast('Enter a cron expression.', 'error'); return; }
    // STEP-UP gated server-side.
    this._mutate('/admin/kms/schedule', { method: 'POST', body: { cron_expr: cron } },
      'Rotation schedule updated.');
  }

  _rotateNow() {
    if (!window.confirm('Trigger an immediate out-of-band KMS key rotation now?')) return;
    // STEP-UP gated server-side.
    this._mutate('/admin/kms/rotate-now', { method: 'POST' }, 'Manual rotation triggered.');
  }

  _renderKms() {
    const k = this._kms;
    const sch = this._schedule;
    const secrets = (this._kmsSecrets && Array.isArray(this._kmsSecrets.secrets)) ? this._kmsSecrets.secrets : [];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">KMS — key management</div>
        <div class="ys-panel-body">
          ${!k ? html`<div class="ys-txt-note">KMS not configured or unavailable.</div>` : html`
            <div class="ys-stat-grid">
              <div class="ys-stat-card">
                <div class="ys-stat-num ys-stat-num--sm">${k.provider || '—'}</div>
                <div class="ys-stat-label">Provider</div>
              </div>
              <div class="ys-stat-card">
                <div class="ys-stat-num">
                  <span class="ys-semaphore ${k.healthy ? 'ys-semaphore--ok' : 'ys-semaphore--critical'}"></span>
                </div>
                <div class="ys-stat-label">${k.healthy ? 'healthy' : (k.health_error || 'unhealthy')}</div>
              </div>
            </div>`}
          <div class="ys-panel-header">Rotation schedule</div>
          ${sch && sch.configured ? html`
            <div class="ys-txt-note">Secret: ${sch.secret_key || '—'} · running: ${sch.running ? 'yes' : 'no'}</div>
          ` : html`<div class="ys-txt-note">No rotation scheduler configured.</div>`}
          <div class="ys-field">
            <label class="ys-label">Cron expression (5-field, ≥1h interval)</label>
            <input class="ys-input" .value=${this._cronInput} placeholder="0 */6 * * *"
                   @input=${(e) => { this._cronInput = e.target.value; }}>
          </div>
          <button class="ys-btn" @click=${() => this._saveSchedule()}>Save schedule</button>
          <button class="ys-btn ys-btn-danger" @click=${() => this._rotateNow()}>Rotate now</button>
          <div class="ys-panel-header">Tracked secret keys</div>
          ${secrets.length
            ? html`<table class="ys-table">
                <thead><tr><th>Key name</th><th>Version</th><th>Created</th></tr></thead>
                <tbody>${secrets.map((s) => html`
                  <tr>
                    <td>${s.key || '—'}</td>
                    <td>${s.version != null ? String(s.version) : '—'}</td>
                    <td>${cleanTs(s.created_at)}</td>
                  </tr>`)}</tbody>
              </table>`
            : html`<div class="ys-txt-note">No tracked secret keys (values are never returned).</div>`}
        </div>
      </div>`;
  }

  _renderVault() {
    const v = this._vault;
    if (!v) return nothing;
    const keys = (v.secrets && Array.isArray(v.secrets.keys)) ? v.secrets.keys : [];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">HashiCorp Vault</div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">Status: ${typeof v.status === 'object' ? JSON.stringify(v.status) : String(v.status)}</div>
          ${keys.length
            ? html`<ul class="ys-alert-list">${keys.map((k) => html`
                <li class="ys-alert-item"><span class="ys-alert-label">${k}</span></li>`)}</ul>`
            : html`<div class="ys-txt-note">No Vault keys listed.</div>`}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading PKI…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <h2 class="ys-admin-section-title">PKI</h2>
        ${this._renderPki()}
        ${this._renderKms()}
        ${this._renderVault()}
        <!-- Crypto & Integrity consolidated under PKI (Tiago 2026-06-28) -->
        <ys-admin-crypto-inventory .api=${this.api} .app=${this.app}></ys-admin-crypto-inventory>
      </div>`;
  }
}

customElements.define('ys-admin-kms-pki', YsAdminKmsPki);

registerAdminModule({
  id: 'pki',
  label: 'PKI',
  icon: '🔑',
  order: 10,
  group: 'platform',
  render: (ctx) => html`
    <ys-admin-kms-pki .api=${ctx.api} .app=${ctx.app}></ys-admin-kms-pki>`,
});
