/**
 * Yashigani 4.0 — User Chat SPA entry point (Phase 2 stub).
 *
 * Trusted-Types policy MUST be installed before any DOM write.
 * The real implementation will import from core/index.js; this stub
 * wires the core layer and renders a "loading" state so the UI shell
 * is exercisable before the full Lit component tree is built.
 *
 * Phase 2 full implementation replaces this file.
 */

// 1. Install Trusted-Types policy (MUST be first — shared-layer-spec §6)
import { installTrustedTypes } from '/static/ui4/core/trusted-types.js';
installTrustedTypes();

// 2. Bootstrap the app container
const root = document.getElementById('app');
if (root) {
  // Safe: system-chrome text only, rendered via textContent (TRUSTED-CHROME)
  const loading = document.createElement('div');
  loading.className = 'ys-card';
  const msg = document.createElement('p');
  msg.className = 'ys-txt-note';
  // textContent — never innerHTML — for system chrome (shared-layer-spec §0 rule 3)
  msg.textContent = 'Yashigani Chat — loading…';
  loading.appendChild(msg);
  root.appendChild(loading);
}
