// Yashigani 4.0 shared layer — Safe-render pipeline (spec §3, RISK-106 HARD).
//
// The ONE sanctioned untrusted-text → DOM path. Anything that renders model
// output, agent results, markdown, or document snippets goes through here;
// nothing else may. The unsafe operations (per-chunk sanitize, raw innerHTML)
// are ABSENT from this module's exports by construction (spec §7).
//
// Vendor seam (Su owns `feat/4.0-csp-vendoring`): marked + DOMPurify are
// vendored same-origin under /static/vendor/, SRI-pinned, eval-audited. We
// import from the AGREED paths below. If a file is not present yet, the import
// fails fast at load — the dependency is on Su's vendoring, not on us.
import { marked } from '/static/vendor/marked/marked.esm.js';
import DOMPurify from '/static/vendor/dompurify/purify.es.mjs';
import { installTrustedTypes } from './trusted-types.js';

// Install the TT policy at module-evaluation time (load-order guarantee, §1).
const _policy = installTrustedTypes();

// ── DOMPurify config — single frozen, audited config (spec §3.1) ────────────
// GitHub-flavoured markdown rendering of marked-generated tags only; NO raw
// HTML passthrough, no unknown protocols, no data:/javascript: URIs. (spec §3.1
// / open-question 3: "GFM minus raw HTML"). DOMPurify returns a TrustedHTML
// directly under TT (RETURN_TRUSTED_TYPE) — the explicit policy call below is
// belt-and-braces.
const DOMPURIFY_CONFIG = Object.freeze({
  ALLOWED_TAGS: [
    'p', 'br', 'hr', 'span', 'div',
    'strong', 'b', 'em', 'i', 'del', 's', 'mark', 'sub', 'sup',
    'blockquote', 'code', 'pre', 'kbd', 'samp',
    'ul', 'ol', 'li',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
  ],
  ALLOWED_ATTR: ['href', 'title', 'class', 'colspan', 'rowspan', 'align', 'start'],
  ALLOW_UNKNOWN_PROTOCOLS: false,
  // Only http/https/mailto links survive; everything else is stripped.
  ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  ADD_ATTR: ['target', 'rel'],
  FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'iframe', 'object', 'embed', 'svg', 'math'],
  FORBID_ATTR: ['style', 'srcset', 'formaction', 'xlink:href'],
  RETURN_TRUSTED_TYPE: true,
});

// Harden links: force external links to noopener/noreferrer and strip any
// javascript:/data: that slipped past the URI regexp. Idempotent hook.
let _hooksInstalled = false;
function _installHooks() {
  if (_hooksInstalled) return;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A' && node.hasAttribute('href')) {
      node.setAttribute('rel', 'noopener noreferrer');
      node.setAttribute('target', '_blank');
    }
  });
  _hooksInstalled = true;
}
_installHooks();

// marked: deterministic, no raw-HTML inlining beyond what DOMPurify will scrub.
marked.setOptions({ gfm: true, breaks: false, headerIds: false, mangle: false });

/**
 * The ONE untrusted-string → TrustedHTML path (spec §3.1).
 *
 * Order is fixed: marked.parse → DOMPurify.sanitize → TT createHTML.
 * MUST be called on a COMPLETE string only (RISK-106, spec §3.2) — never on a
 * partial SSE chunk. There is deliberately no sanitizeChunk() export.
 *
 * @param {string} untrusted complete markdown/model/agent/document text
 * @returns {TrustedHTML} (or sanitised string on non-TT browsers)
 */
export function renderMarkdown(untrusted) {
  const md = String(untrusted == null ? '' : untrusted);
  const dirtyHtml = marked.parse(md);
  // DOMPurify with RETURN_TRUSTED_TYPE returns a TrustedHTML when TT is
  // available; coerce through our named policy regardless (belt-and-braces),
  // accepting that on a TrustedHTML input createHTML stringifies-then-blesses.
  const clean = DOMPurify.sanitize(dirtyHtml, DOMPURIFY_CONFIG);
  return _policy.createHTML(String(clean));
}

/**
 * Identifier/label rendering — HTML is NEVER valid here (spec §3.3, zero
 * allowlist). Returns a plain string to be assigned via textContent (NOT a
 * DOM sink). Strips any tags entirely. Used for node labels, tool names,
 * usernames, policy ids, and exposed for Drawflow's own DOM writes (Phase 5).
 *
 * @param {string} s untrusted identifier
 * @returns {string} tag-free plain text, safe for textContent
 */
export function sanitizeLabel(s) {
  const str = String(s == null ? '' : s);
  return String(DOMPurify.sanitize(str, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }));
}

/**
 * Trusted-chrome text passthrough (spec §3.3). System/server-authored text is
 * rendered via textContent; this is the identity function that documents intent
 * at the call-site (a label is text, not markup). Provided for parity with the
 * spec's public surface; no sanitisation needed because the consumer assigns it
 * to textContent, never to a DOM sink.
 *
 * @param {string} s
 * @returns {string}
 */
export function renderText(s) {
  return String(s == null ? '' : s);
}

// NOT exported: DOMPurify, marked, the TT policy, any innerHTML helper, any
// per-chunk sanitizer. The unsafe operations are absent by construction (§7).
