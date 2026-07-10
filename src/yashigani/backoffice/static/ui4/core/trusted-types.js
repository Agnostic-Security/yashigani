// Yashigani 4.0 shared layer — Trusted-Types policy interface (spec §6).
//
// Registers the SINGLE named safe-HTML policy `yashigani-render` (R1/R8). There
// is NO `default` TT policy — fail-closed: any sink hit without a TrustedHTML
// throws a CSP violation. This module MUST be the first import in every entry
// point so the policy is registered before any sink runs (spec §1 load order).
//
// `createHTML` does NOT sanitise; it asserts "this string already passed the
// §3 pipeline". It is called ONLY by safe-render.js (and DOMPurify's
// RETURN_TRUSTED_TYPE). Centralising it makes one auditable line the gate for
// every DOM-XSS-capable write.
//
// Cross-spec seam (Su): the CSP header MUST list exactly `trusted-types
// yashigani-render; require-trusted-types-for 'script'`. Browser support is
// Chromium-only; on Firefox/Safari this degrades to a pass-through shim and
// DOMPurify (§3) remains the real defence (spec §6.2 — documented residual).

export const TT_POLICY_NAME = 'yashigani-render';

let _policy = null;

/**
 * Install (idempotent) the named Trusted-Types policy. Called at first import
 * of safe-render.js. Returns an object exposing `createHTML(string)`.
 *
 * On a TT-capable browser this returns a real TrustedTypePolicy. On a
 * non-supporting browser it returns a shim whose createHTML is the identity
 * function — sanitisation (DOMPurify) is still applied upstream, TT is the
 * defence-in-depth layer that only upgrades DOM-XSS to a CSP violation.
 */
export function installTrustedTypes() {
  if (_policy) return _policy;

  const tt = typeof window !== 'undefined' ? window.trustedTypes : undefined;
  if (tt && typeof tt.createPolicy === 'function') {
    try {
      _policy = tt.createPolicy(TT_POLICY_NAME, {
        // Identity: the string has already been through marked → DOMPurify.
        // This policy NEVER sanitises — that is safe-render.js's job.
        createHTML: (s) => s,
      });
    } catch (err) {
      // A policy with this name may already exist (e.g. duplicate module
      // evaluation in a test harness). Re-create is not allowed, so fall back
      // to the shim; the upstream DOMPurify pass is what protects us.
      _policy = { createHTML: (s) => s, name: TT_POLICY_NAME, _shim: true };
    }
  } else {
    // Non-Chromium / no TT support: pass-through shim (spec §6.2 residual).
    _policy = { createHTML: (s) => s, name: TT_POLICY_NAME, _shim: true };
  }
  return _policy;
}

/** Return the installed policy, installing it on first use. */
export function getPolicy() {
  return _policy || installTrustedTypes();
}
