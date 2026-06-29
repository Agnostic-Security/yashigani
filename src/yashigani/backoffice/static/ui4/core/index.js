// Yashigani 4.0 shared layer — public API surface (barrel, spec §7).
//
// Anything NOT re-exported here is private to the layer. Notably there is NO
// exported way to sanitize a chunk, to write innerHTML, or to decode from free
// text — the unsafe operations are absent by construction (RISK-105/106).
//
// trusted-types.js is imported FIRST (transitively via safe-render.js) so the
// policy is registered before any sink runs (spec §1 load order).

export { installTrustedTypes, TT_POLICY_NAME } from './trusted-types.js';
export { ApiClient } from './api-client.js';
export { renderMarkdown, renderText, sanitizeLabel } from './safe-render.js';
export { streamChat } from './sse.js';
export { decodeVerdict } from './decode.js';
export { LEGEND } from './decode-legend.js';
export * as widgets from './widgets/index.js';

// NOT exported: DOMPurify, marked, the TT policy object, any innerHTML helper,
// any per-chunk sanitizer.
