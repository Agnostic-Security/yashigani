/**
 * safe-render.js — Trusted Types policy for yashigani-render
 *
 * This module is the SOLE registrant of the 'yashigani-render' TT policy.
 * No other module may call trustedTypes.createPolicy().
 *
 * Policy name: yashigani-render  (canonical — matches CSP trusted-types directive
 * in docker/Caddyfile.csp @strict_tt and RECONCILIATION-20260627.md R1/R8)
 *
 * Returns TrustedHTML from the marked → DOMPurify → TrustedTypes pipeline.
 * Requires:
 *   - DOMPurify >= 2.4.0 for RETURN_TRUSTED_TYPE: true support (spec §3.7)
 *   - DOMPurify and marked available as globals (imported via <script> SRI tags
 *     from /static/vendor/dompurify/purify-3.4.11.min.js and
 *     /static/vendor/marked/marked-18.0.5.min.js)
 *
 * Usage (from shared-layer/chat.js or similar):
 *   import { safeRenderMarkdown } from '/static/vendor/shared-layer/safe-render.js';
 *   element.innerHTML = safeRenderMarkdown(llmResponseText);
 *
 * INVARIANTS (from spec §2.3):
 *   1. This policy is called on the COMPLETE accumulated message, not per SSE token.
 *      The SSE helper in shared-layer must buffer until stream closes before calling.
 *   2. Verdict/chrome rendering ([BLOCKED BY YASHIGANI] etc.) uses textContent only —
 *      never passes through this policy (spec §2.3 / RISK-105).
 *   3. No 'default' TT policy is registered anywhere — fail-closed on unreviewed
 *      DOM writes (spec §2.2 / RECONCILIATION-20260627.md R1).
 */

/* global trustedTypes, DOMPurify, marked */

// Guard: TrustedTypes API must be available (supported browsers under @strict_tt CSP).
// In Phase 2, the UI code runs exclusively on these paths. If somehow loaded on a
// legacy path without TT enforcement, the policy registration is a no-op and
// safeRenderMarkdown falls back to DOMPurify plain string (defense-in-depth only).
const hasTT = (typeof trustedTypes !== 'undefined' && trustedTypes.createPolicy);

/**
 * The yashigani-render TrustedTypes policy.
 * Sole permitted path for rendering untrusted content (LLM output, document excerpts,
 * template descriptions). All other innerHTML calls are TT violations.
 */
const yashiganiRender = hasTT
    ? trustedTypes.createPolicy('yashigani-render', {
        createHTML(dirty) {
            // Step 1: marked → parse Markdown to HTML string.
            // Use synchronous mode (async: false). No gfm extensions that open
            // attack surface (no custom renderer, no mangle, no pedantic).
            const parsed = marked.parse(dirty, {
                async: false,
                gfm: true,
                breaks: false,
            });

            // Step 2: DOMPurify sanitize → TrustedHTML
            // RETURN_TRUSTED_TYPE: true requires DOMPurify >= 2.4.0.
            // FORBID_TAGS/FORBID_ATTR are defence-in-depth (DOMPurify's defaults
            // already strip script/on*; we add style/iframe/object/embed explicitly).
            return DOMPurify.sanitize(parsed, {
                RETURN_TRUSTED_TYPE: true,
                USE_PROFILES: { html: true },
                FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'base'],
                FORBID_ATTR: [
                    'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
                    'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
                    'onkeyup', 'onkeypress', 'style',
                ],
            });
        },
    })
    : null;

/**
 * Render untrusted Markdown content safely via the yashigani-render TT policy.
 *
 * @param {string} markdown — untrusted Markdown string (e.g. LLM chat response)
 * @returns {TrustedHTML|string} — TrustedHTML when TT is enforced, sanitized
 *   HTML string as fallback (for environments without TT enforcement).
 *
 * IMPORTANT: call this only on the COMPLETE accumulated message (not per SSE token).
 */
export function safeRenderMarkdown(markdown) {
    if (!yashiganiRender) {
        // Fallback for environments where TrustedTypes is not enforced.
        // Should not occur on @strict_tt paths in production.
        const parsed = marked.parse(markdown, { async: false, gfm: true, breaks: false });
        return DOMPurify.sanitize(parsed, {
            USE_PROFILES: { html: true },
            FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'base'],
            FORBID_ATTR: [
                'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
                'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
                'onkeyup', 'onkeypress', 'style',
            ],
        });
    }
    return yashiganiRender.createHTML(markdown);
}

/**
 * Set element.innerHTML to rendered, sanitized Markdown.
 * Convenience wrapper — use this instead of element.innerHTML = ... directly.
 *
 * @param {Element} element — target DOM element
 * @param {string} markdown — untrusted Markdown content
 */
export function renderMarkdownInto(element, markdown) {
    element.innerHTML = safeRenderMarkdown(markdown);
}
