// Yashigani 4.0 admin shell — Identity & Access shared helpers (Wave-2).
//
// Small, dependency-light utilities reused across the IAM module group
// (accounts, users, rbac, scim, sso, webauthn, hibp, ratelimit). No DOM sinks
// here beyond the audited ys-modal step-up prompt — everything renders through
// Lit auto-escape in the module elements themselves (TRUSTED-CHROME, §3 markdown
// sink never used: these surfaces show server-authored config only).
import { widgets } from '../../core/index.js';

void widgets; // retain side-effect import (ys-* custom elements incl. ys-modal).

/**
 * RISK-103 client-enforced step-up.
 *
 * Some re-tiered dangerous mutations (RBAC policy force-push, RBAC group/member
 * mutations, SCIM interactive writes) are served by routes that still carry a
 * plain AdminSession server-side, so the ApiClient's server-driven step-up
 * interceptor never fires for them. This helper makes those mutations NON
 * one-click: it prompts for a fresh TOTP via the shared step-up modal and
 * elevates the session through /auth/stepup BEFORE the caller issues the write.
 *
 * Routes that already carry StepUpAdminSession (accounts/users/hibp/jwt/webauthn
 * delete) MUST NOT be wrapped — the ApiClient interceptor handles those, and
 * double-gating would prompt twice.
 *
 * @param {import('../../core/api-client.js').ApiClient} api  shared admin client
 * @param {string} message  human-readable reason shown in the step-up modal
 * @returns {Promise<boolean>} true when the session was successfully elevated
 */
export async function elevate(api, message) {
  const code = await widgets.promptStepUp({ message });
  if (!code) return false; // operator cancelled — abort the mutation.
  try {
    const resp = await fetch('/auth/stepup', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Yashigani-Plane': api.sessionKind,
      },
      body: JSON.stringify({ totp: code }),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

/**
 * Toast the outcome of an ApiClient.mutate() Result via the shell's app.toast.
 * `error.message` is SERVER-AUTHORED and rendered as trusted chrome (textContent
 * inside ys-toast) — never through the markdown pipeline.
 * @returns {boolean} res.ok
 */
export function reportMutate(app, res, okMsg) {
  if (res && res.ok) {
    if (app && typeof app.toast === 'function') app.toast(okMsg || 'Saved.', 'success');
    return true;
  }
  const msg = (res && res.error && res.error.message) || 'Request failed.';
  if (app && typeof app.toast === 'function') app.toast(msg, 'error');
  return false;
}

/** Boolean → short yes/no label for table cells. */
export function yn(v) {
  return v ? 'yes' : 'no';
}

/** Trim an ISO timestamp to date+minute for compact table display. */
export function shortTs(iso) {
  if (!iso || typeof iso !== 'string') return '';
  return iso.replace('T', ' ').slice(0, 16);
}
