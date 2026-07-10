// Yashigani 4.0 shared layer — clipboard helper (TRUSTED-CHROME, internal).
//
// Copies plain text to the clipboard for the "copy message" / "copy code"
// affordances. NOT a render path: it never writes to a DOM HTML sink, never
// touches innerHTML, and only ever handles a plain string. Deliberately NOT
// re-exported from index.js — it is an internal chrome utility, not part of the
// audited public surface (spec §7).
//
// CSP-clean: the execCommand fallback positions an off-screen <textarea> via the
// CSSOM `.style` property (a programmatic assignment, NOT a parsed style="..."
// attribute string), the same pattern used by ys-user-sidebar for the budget
// bar — so it does not trip `style-src` without 'unsafe-inline'.

/**
 * Copy `text` to the clipboard. Resolves true on success, false otherwise.
 * Never throws (so a denied permission in a sandboxed/headless context cannot
 * surface an uncaught error to the console).
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyText(text) {
  const s = String(text == null ? '' : text);
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(s);
      return true;
    }
  } catch {
    // Fall through to the execCommand path (e.g. no permission / not focused).
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = s;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-9999px';
    ta.style.left = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = !!(document.execCommand && document.execCommand('copy'));
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}
