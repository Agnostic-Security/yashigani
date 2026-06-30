// Yashigani 4.0 admin shell — Monitoring module ("Observability" group).
//
// Surfaces the operator-facing observability tools INSIDE the admin webui, each
// behind the SAME same-origin, admin-gated reverse-proxy paths Su owns
// (feat/4.0-csp-proxy):
//   /admin/grafana/        → Grafana (metrics dashboards)
//   /admin/wazuh/          → Wazuh SIEM console (security events, opt-in profile)
//   /admin/grafana/explore → Loki logs (via Grafana Explore, Loki datasource)
//   /admin/alertmanager/   → Prometheus Alertmanager
//
// LOKI: Loki has no standalone web UI — it is a query API consumed by Grafana.
// The Loki tile embeds Grafana Explore preset to the Loki datasource (uid: 'loki').
//
// WAZUH: Wazuh is an OPTIONAL compose profile (--wazuh install flag). When not
// deployed, the /admin/wazuh/ proxy returns 502. On connectedCallback we call
// /admin/services to check the enabled profile list; if wazuh is absent we
// immediately set the tile to 'absent' and render a "not deployed" banner instead
// of the generic "down" message.
//
// SEAM (Su, PINNED): these paths are served same-origin and admin-gated; Su sets
// `frame-src 'self'` and strips the frame-deny headers (X-Frame-Options /
// frame-ancestors) on the proxied responses so they are embeddable. Because the
// frames are SAME-ORIGIN they load under `frame-src 'self'` (and the strict
// default-src 'self' fallback) with no CSP relaxation on our side.
//
// TRUSTED-CHROME ONLY: every label/note rendered here is an author-defined
// constant or a tool label, emitted via Lit text bindings (textContent). No
// model/agent/document output reaches this surface, so the §3 markdown sink is
// never touched and there is no untrusted HTML. The <iframe> src is an author
// constant; iframe `src` is not a Trusted-Types sink. We deliberately import
// ONLY Lit + the registry (no core barrel) — this surface needs neither the
// ApiClient data path nor the markdown pipeline.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { registerAdminModule } from '../module-registry.js';

// Grafana Explore URL preset to the Loki datasource (uid: 'loki', provisioned
// via config/grafana/provisioning/datasources/loki.yml). Loki has no standalone
// web UI; Grafana Explore is the correct consumer for log browsing.
const _LOKI_EXPLORE_SRC = '/admin/grafana/explore?orgId=1&left=' +
  encodeURIComponent(JSON.stringify({
    datasource: 'loki',
    queries: [{ refId: 'A', expr: '{job=~".+"}', queryType: 'range' }],
    range: { from: 'now-1h', to: 'now' },
  }));

// Tool catalogue — author-defined constants (TRUSTED-CHROME). `src` is a
// same-origin, admin-gated proxied path (Su's seam). Order here = tab order.
// `serviceId` (optional): the /admin/services API id that controls deployment;
// when the service is not running the tile renders an absent banner instead of
// probing a 502.
const TOOLS = Object.freeze([
  {
    key: 'grafana',
    label: 'Grafana',
    src: '/admin/grafana/',
    desc: 'Metrics dashboards (Grafana). Opens the governed, admin-gated tool.',
  },
  {
    key: 'wazuh',
    label: 'SIEM (Wazuh)',
    src: '/admin/wazuh/',
    serviceId: 'wazuh',  // optional compose profile; may not be deployed
    desc: 'Wazuh SIEM console — security events & alerts. Opens the governed, admin-gated tool.',
  },
  {
    key: 'loki',
    label: 'Logs (Loki)',
    src: _LOKI_EXPLORE_SRC,
    desc: 'Centralised logs browsed via Grafana Explore (Loki datasource). Opens the governed, admin-gated tool.',
  },
  {
    key: 'alertmanager',
    label: 'Alertmanager',
    src: '/admin/alertmanager/',
    desc: 'Prometheus Alertmanager — active alerts & silences. Opens the governed, admin-gated tool.',
  },
]);

// Embedding posture for the proxied tools. allow-same-origin is REQUIRED for
// Grafana/Wazuh to function (their session cookie + storage); it is safe here
// because the framed document is our OWN governed, admin-gated proxy on the same
// origin — not third-party content.
const SANDBOX = [
  'allow-same-origin',
  'allow-scripts',
  'allow-forms',
  'allow-popups',
  'allow-popups-to-escape-sandbox',
  'allow-downloads',
  'allow-modals',
].join(' ');

export class YsAdminMonitoring extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _active: { state: true },   // currently selected tool key
    _seen: { state: true },     // Set<key> of tools mounted at least once (lazy)
    _status: { state: true },   // { [key]: 'unknown'|'checking'|'ok'|'down'|'absent' }
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._active = TOOLS[0].key;
    this._seen = new Set([TOOLS[0].key]);
    this._status = {};
  }

  // Light DOM (mirror the other admin modules) so design-system classes apply
  // and the iframes live in the document tree.
  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    // Check which optional services are actually deployed before probing so
    // tools like Wazuh (optional profile) show a clear "not deployed" state
    // rather than the generic "proxy returned an error" error banner.
    this._checkServices().then(() => {
      // Only probe if not already marked absent by the services check.
      if (this._status[this._active] !== 'absent') {
        this._probe(this._active);
      }
    });
  }

  /**
   * Query /admin/services to determine which optional-profile tools are
   * deployed in this installation. Tools whose serviceId is not in the running
   * set are marked 'absent' immediately — no proxy probe needed/desired.
   */
  async _checkServices() {
    try {
      const res = await fetch('/admin/services', {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (!res.ok) return;
      const data = await res.json();
      const runningIds = new Set(
        (data.services || [])
          .filter((s) => s.status === 'running')
          .map((s) => s.id),
      );
      const updates = {};
      for (const t of TOOLS) {
        if (t.serviceId && !runningIds.has(t.serviceId)) {
          updates[t.key] = 'absent';
        }
      }
      if (Object.keys(updates).length) {
        this._status = { ...this._status, ...updates };
      }
    } catch (_) {
      // Non-fatal: if /admin/services is unreachable we fall back to probe-only.
    }
  }

  _select(key) {
    if (!TOOLS.some((t) => t.key === key)) return;
    if (!this._seen.has(key)) this._seen = new Set([...this._seen, key]);
    this._active = key;
    // Re-probe a tool when it becomes active so a transient proxy outage that
    // has since recovered clears the banner. Skip absent tools.
    const st = this._status[key];
    if (st !== 'ok' && st !== 'absent') this._probe(key);
  }

  /**
   * Lightweight same-origin reachability probe. iframes don't surface HTTP
   * errors (a 502 body still fires `load`), so we ask the proxy directly and
   * drive a graceful banner from the result. Never throws — a failed probe is
   * just 'down'.
   */
  async _probe(key) {
    const tool = TOOLS.find((t) => t.key === key);
    if (!tool) return;
    this._status = { ...this._status, [key]: 'checking' };
    let ok = false;
    try {
      const res = await fetch(tool.src, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'follow',
      });
      ok = res.ok || res.status === 401 || res.status === 403; // reachable (auth handled by the framed tool)
    } catch (_err) {
      ok = false;
    }
    this._status = { ...this._status, [key]: ok ? 'ok' : 'down' };
  }

  _renderTabs() {
    return html`
      <div class="ys-mon-tabs" role="tablist" aria-label="Monitoring tools">
        ${TOOLS.map((t) => html`
          <button
            class="ys-mon-tab ${t.key === this._active ? 'ys-mon-tab--active' : ''}"
            role="tab"
            aria-selected=${t.key === this._active ? 'true' : 'false'}
            @click=${() => this._select(t.key)}
          >${t.label}</button>`)}
      </div>`;
  }

  _renderDownBanner(t) {
    return html`
      <div class="ys-panel ys-mon-down">
        <div class="ys-panel-body ys-mon-down-body">
          <span class="ys-semaphore ys-semaphore--degraded"></span>
          <span class="ys-mon-down-msg">${t.label} is not reachable right now — the governed proxy returned an error or the tool is still starting up.</span>
          <button class="ys-btn ys-btn-secondary" @click=${() => this._probe(t.key)}>Retry</button>
        </div>
      </div>`;
  }

  /**
   * Render a "not deployed" notice for tools whose optional compose profile is
   * absent. Names the exact install flag so the operator knows how to enable it.
   */
  _renderAbsentBanner(t) {
    const flag = t.serviceId ? `--${t.serviceId}` : '(enable at install time)';
    return html`
      <div class="ys-panel ys-mon-down">
        <div class="ys-panel-body ys-mon-down-body">
          <span class="ys-semaphore ys-semaphore--info"></span>
          <span class="ys-mon-down-msg">
            ${t.label} is not deployed in this profile.
            To enable it, re-run the installer with
            <strong>${flag}</strong> — this is an in-place upgrade that preserves data volumes.
          </span>
        </div>
      </div>`;
  }

  _renderPane(t) {
    if (!this._seen.has(t.key)) return nothing; // lazy: only mount once activated
    const active = t.key === this._active;
    const status = this._status[t.key];
    const down = status === 'down';
    const absent = status === 'absent';
    return html`
      <section
        class="ys-mon-pane ${active ? '' : 'ys-mon-pane--hidden'}"
        role="tabpanel"
        ?hidden=${!active}
      >
        <div class="ys-mon-bar">
          <span class="ys-txt-note">${t.desc}</span>
          ${absent ? nothing : html`
            <a class="ys-btn ys-btn-secondary ys-mon-newtab"
               href=${t.src} target="_blank" rel="noopener noreferrer"
            >Open in new tab ↗</a>`}
        </div>
        ${absent
          ? this._renderAbsentBanner(t)
          : down
            ? this._renderDownBanner(t)
            : nothing}
        ${absent ? nothing : html`
          <iframe
            class="ys-mon-frame"
            src=${t.src}
            title=${t.label}
            sandbox=${SANDBOX}
            referrerpolicy="no-referrer"
            loading="lazy"
          ></iframe>`}
      </section>`;
  }

  render() {
    return html`
      <div class="ys-admin-content-pad ys-mon-root">
        <h2 class="ys-admin-section-title">Monitoring</h2>
        <p class="ys-txt-note ys-mon-intro">Observability tools are embedded read-through the same-origin, admin-gated gateway. Each opens the governed tool — actions inside it are subject to the tool's own auth.</p>
        ${this._renderTabs()}
        ${TOOLS.map((t) => this._renderPane(t))}
      </div>`;
  }
}

customElements.define('ys-admin-monitoring', YsAdminMonitoring);

registerAdminModule({
  id: 'monitoring',
  label: 'Monitoring',
  icon: '📈',
  order: 10,
  group: 'overview',
  render: (ctx) => html`
    <ys-admin-monitoring .api=${ctx.api} .app=${ctx.app}></ys-admin-monitoring>`,
});
