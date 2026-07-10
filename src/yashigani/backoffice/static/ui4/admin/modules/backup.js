// Yashigani 4.0 admin shell — Backup & Restore module ("Ops & Crypto" group).
//
// Rebuilds the 3.0 backup panel (BK-01/02/03) on the hardened shell:
//   GET  /admin/backup/status   → list backups + MANIFEST integrity state
//   POST /admin/backup/verify   → re-hash a backup vs MANIFEST.sha256
//   POST /admin/backup/create   → take a new DB snapshot (STEP-UP)
//
// Restore: there is NO admin restore API by design — restore is the operator
// CLI `restore.sh` (it stops services, swaps volumes, and must run on the host).
// The module surfaces that explicitly and flags that, were an in-console restore
// ever added, it would be the single most dangerous op and MUST be step-up gated
// (RISK-103). This is a deliberate non-gap, recorded here rather than faked.
//
// Encryption: ALL on-demand backups are AES-256-GCM encrypted + HMAC-SHA384
// signed (B12 policy, see backup.py _encrypt_and_sign_backup).  The key is the
// per-install YASHIGANI_DB_AES_KEY — no passphrase is required and unencrypted
// backups are not offered.  The create modal makes this explicit rather than
// hiding it inside a window.confirm().
//
// TRUSTED-CHROME: backup names, sizes, timestamps and integrity verdicts are
// server-authored and rendered via Lit auto-escape — no §3 markdown sink. The
// dangerous op (create) is StepUpAdminSession server-side, so ctx.api.mutate
// makes the shell's TOTP step-up fire transparently.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

function fmtBytes(n) {
  const b = Number(n);
  if (!Number.isFinite(b) || b <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = b; let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function manifestBadge(state) {
  if (state === 'signed') return html`<span class="ys-badge ys-badge-green">signed</span>`;
  if (state === 'unsigned') return html`<span class="ys-badge ys-badge-amber">unsigned</span>`;
  if (state === 'corrupt') return html`<span class="ys-badge ys-badge-red">corrupt</span>`;
  return html`<span class="ys-badge ys-badge-blue">${state || 'unknown'}</span>`;
}

export class YsAdminBackup extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading:     { state: true },
    _status:      { state: true },
    _verify:      { state: true },   // last verify result | null
    _busy:        { state: true },
    _showCreate:  { state: true },   // create-backup confirmation modal open
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._status = null;
    this._verify = null;
    this._busy = false;
    this._showCreate = false;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    this._status = await this.api.get('/admin/backup/status');
    this._loading = false;
  }

  _toast(msg, kind) { if (this.app && this.app.toast) this.app.toast(msg, kind); }

  _backups() {
    return (this._status && Array.isArray(this._status.backups)) ? this._status.backups : [];
  }

  // ── Create backup ─────────────────────────────────────────────────────────

  // Open the confirmation modal instead of using window.confirm().
  _openCreate() {
    this._showCreate = true;
  }

  async _doCreate() {
    this._showCreate = false;
    if (this._busy) return;
    this._busy = true;
    // STEP-UP gated server-side (StepUpAdminSession) → TOTP modal fires via mutate.
    const res = await this.api.mutate('/admin/backup/create', { method: 'POST' });
    this._busy = false;
    if (res.ok) {
      this._toast('Backup created.', 'success');
      // Refresh the backup list from the server.
      await this._load();
      // Fallback: if _load() returned null (transient GET error), synthesize
      // the new entry from the create response so it appears immediately.
      if (!this._status && res.data && res.data.backup_name) {
        this._status = {
          backups: [{
            name: res.data.backup_name,
            type: res.data.type || 'ondemand',
            created_at: res.data.created_at || null,
            manifest_state: res.data.signed ? 'signed' : 'unsigned',
            size_bytes: res.data.size_bytes || 0,
            files: [],
          }],
          latest: null,
          backups_dir: 'backups',
        };
      }
    } else {
      this._toast((res.error && res.error.message) || 'Backup creation failed.', 'error');
    }
  }

  // ── Verify backup ─────────────────────────────────────────────────────────

  async _verifyBackup(name) {
    if (this._busy) return;
    this._busy = true;
    this._verify = null;
    const res = await this.api.mutate('/admin/backup/verify', { method: 'POST', body: { backup_name: name } });
    this._busy = false;
    if (res.ok) {
      this._verify = res.data;
      this._toast(res.data && res.data.ok ? `Integrity OK: ${name}` : `Integrity check finished: ${name}`,
        res.data && res.data.ok ? 'success' : 'info');
    } else {
      this._toast((res.error && res.error.message) || 'Verify failed.', 'error');
    }
  }

  // ── Render helpers ─────────────────────────────────────────────────────────

  _renderVerifyResult() {
    const v = this._verify;
    if (!v) return nothing;
    const mismatches = Array.isArray(v.mismatches) ? v.mismatches : [];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Verify result — ${v.backup_name || ''}
          ${v.ok ? html`<span class="ys-badge ys-badge-green">ok</span>` : html`<span class="ys-badge ys-badge-red">failed</span>`}
        </div>
        <div class="ys-panel-body">
          <div class="ys-txt-note">Manifest state: ${v.manifest_state || '—'} · verified at ${v.verified_at || '—'}</div>
          ${mismatches.length
            ? html`<ul class="ys-alert-list">${mismatches.map((m) => html`
                <li class="ys-alert-item">
                  <span class="ys-semaphore ys-semaphore--critical"></span>
                  <span class="ys-alert-label">${typeof m === 'string' ? m : JSON.stringify(m)}</span>
                </li>`)}</ul>`
            : html`<div class="ys-txt-note">No checksum mismatches.</div>`}
        </div>
      </div>`;
  }

  _renderCreateModal() {
    if (!this._showCreate) return nothing;
    return html`
      <div class="ys-modal-backdrop"
           @click=${(ev) => { if (ev.target === ev.currentTarget) this._showCreate = false; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Create backup snapshot</div>
          <div class="ys-modal-body">

            <!-- Encryption status — always on, no opt-out (B12 policy) -->
            <div class="ys-field">
              <label class="ys-label">
                <input type="checkbox" checked disabled aria-disabled="true">
                &nbsp;Encrypt backup
              </label>
              <div class="ys-txt-note">
                Always-on per B12 security policy — backups are
                <strong>AES-256-GCM encrypted</strong> (per-backup DEK wrapped under
                an HKDF-SHA384 KEK) and <strong>HMAC-SHA384 signed</strong>.
                The encryption key is the per-install
                <code class="ys-system-chrome-code">YASHIGANI_DB_AES_KEY</code>;
                recovery requires that key — no passphrase is involved.
              </div>
            </div>

            <div class="ys-txt-note">
              A consistent database snapshot will be taken now.
              This is a <strong>step-up action</strong> — a fresh TOTP code is
              required to confirm.
            </div>
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn ys-btn-secondary"
                    @click=${() => { this._showCreate = false; }}>Cancel</button>
            <button class="ys-btn"
                    ?disabled=${this._busy}
                    @click=${() => this._doCreate()}>
              ${this._busy ? 'Creating…' : 'Create backup (step-up)'}
            </button>
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading backups…</div></div>`;
    }
    const backups = this._backups();
    return html`
      <div class="ys-admin-content-pad">
        <h2 class="ys-admin-section-title">Backup &amp; Restore</h2>
        <div class="ys-panel">
          <div class="ys-panel-header">Backups</div>
          <div class="ys-panel-body">
            <button class="ys-btn" ?disabled=${this._busy} @click=${() => this._openCreate()}>
              ${this._busy ? 'Working…' : 'Create backup'}
            </button>
            ${backups.length === 0
              ? html`<div class="ys-txt-note">No backups found in ${this._status ? this._status.backups_dir : 'backups/'}.</div>`
              : html`<table class="ys-table">
                  <thead><tr><th>Name</th><th>Type</th><th>Created</th><th>Integrity</th><th>Size</th><th>Actions</th></tr></thead>
                  <tbody>
                    ${backups.map((b) => html`
                      <tr>
                        <td>${b.name}</td>
                        <td>${b.type || '—'}</td>
                        <td>${b.created_at || '—'}</td>
                        <td>${manifestBadge(b.manifest_state)}</td>
                        <td>${fmtBytes(b.size_bytes)}</td>
                        <td><button class="ys-btn ys-btn-ghost" ?disabled=${this._busy}
                              @click=${() => this._verifyBackup(b.name)}>Verify</button></td>
                      </tr>`)}
                  </tbody>
                </table>`}
          </div>
        </div>
        ${this._renderVerifyResult()}
        <div class="ys-panel">
          <div class="ys-panel-header">
            Restore <span class="ys-badge ys-badge-amber">operator CLI</span>
          </div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">
              Restore is intentionally not a one-click console action. It stops services and
              swaps data volumes, so it runs on the host via <code class="ys-system-chrome-code">restore.sh &lt;backup-name&gt;</code>.
              Verify a backup's integrity above before restoring. If an in-console restore is
              ever added it will be the most dangerous op in the product and must be step-up gated (RISK-103).
            </div>
          </div>
        </div>
        ${this._renderCreateModal()}
      </div>`;
  }
}

customElements.define('ys-admin-backup', YsAdminBackup);

registerAdminModule({
  id: 'backup',
  label: 'Backup & Restore',
  icon: '💾',
  order: 30,
  group: 'platform',
  render: (ctx) => html`
    <ys-admin-backup .api=${ctx.api} .app=${ctx.app}></ys-admin-backup>`,
});
