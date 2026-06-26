// Yashigani 4.0 shared layer — canary / XSS self-test (spec §10 acceptance).
//
// Exercises the safe-render pipeline and proves XSS payloads render INERT,
// including a payload split across SSE chunk boundaries (RISK-106). Also proves
// the decode() HARD contract (structured-only, RISK-105) and the verdict banner.
//
// Results are written to window.__CANARY_RESULT for a headless harness and
// rendered to the page. Any executed payload calls window.__xss(tag) → FAIL.
import {
  renderMarkdown, sanitizeLabel, decodeVerdict, ApiClient, TT_POLICY_NAME,
} from '/static/ui4/core/index.js';
import { streamChat } from '/static/ui4/core/sse.js';

const results = [];
window.__xssFired = [];
window.__xss = (tag) => { window.__xssFired.push(tag); };

function check(name, pass, detail) {
  results.push({ name, pass: !!pass, detail: detail || '' });
}

function noXss() { return window.__xssFired.length === 0; }

// Inertness test: a payload is inert if the OUTPUT contains no LIVE element with
// an event-handler attribute and no LIVE <script>. Entity-escaped text (e.g.
// "&lt;img ... onerror=...&gt;") is harmless visible text — substring-matching
// "onerror" would false-fail on it. We test for live-tag forms only. The
// ultimate proof is that window.__xss() is never called (check at the end).
function hasLiveHandler(s) { return /<[a-z][^>]*\son\w+\s*=/i.test(s); }
function hasLiveScript(s) { return /<script[\s>]/i.test(s); }

// 1. Basic markdown renders, and an inline <img onerror> payload is inert.
const payload1 = 'hello **world** <img src=x onerror="window.__xss(\'img\')">';
const out1 = renderMarkdown(payload1);
const s1 = String(out1);
check('markdown renders bold', /<strong>world<\/strong>/.test(s1), s1.slice(0, 120));
check('inline img onerror stripped', !hasLiveHandler(s1), s1);

// 2. <script> payload is stripped.
const out2 = String(renderMarkdown('<script>window.__xss("script")<\/script> ok'));
check('script tag stripped', !hasLiveScript(out2) && !hasLiveHandler(out2), out2);

// 3. javascript: URI link is neutralised.
const out3 = String(renderMarkdown('[click](javascript:window.__xss("jsuri"))'));
check('javascript: uri neutralised', !/javascript:/i.test(out3), out3);

// 4. Split-across-chunks payload (RISK-106). The unsafe bytes
//    "hello <img src=x" | " onerror=window.__xss('split')>" only form an attack
//    if sanitised per-chunk. The layer NEVER sanitises per chunk; it accumulates
//    and calls renderMarkdown ONCE on the complete string. Simulate that here.
const chunkA = 'hello <img src=x';
const chunkB = ' onerror=window.__xss(\'split\')>';
let accumulated = '';
accumulated += chunkA; // shown as textContent only while streaming (no parse)
accumulated += chunkB;
const outSplit = String(renderMarkdown(accumulated)); // single call on COMPLETE str
check('split-chunk payload inert', !hasLiveHandler(outSplit) && !hasLiveScript(outSplit), outSplit);

// 4b. Prove there is no per-chunk sanitizer exported (structural, RISK-106).
import('/static/ui4/core/safe-render.js').then((mod) => {
  check('no sanitizeChunk export', typeof mod.sanitizeChunk === 'undefined'
    && typeof mod.sanitizeFragment === 'undefined');
  finalise();
});

// 5. sanitizeLabel strips all tags to plain text.
const lbl = sanitizeLabel('<b onclick="window.__xss(\'lbl\')">node</b>');
check('sanitizeLabel zero-allowlist', lbl === 'node', lbl);

// 6. decode() HARD contract — structured input only; a raw string throws.
let threw = false;
try { decodeVerdict('64F7:1:0:8:7:14'); } catch (e) { threw = e instanceof TypeError; }
check('decode rejects free-text string (RISK-105)', threw);

// 7. decode() on a structured field resolves the legend.
const decoded = decodeVerdict({
  decision_codes: ['64F7:1:0:8:7:14'],
  user_alert: { user_message: 'Response exceeded your clearance.', policy_id: 'POL-CLEARANCE' },
});
check('decode structured: sentinel set', decoded.sentinel === true);
check('decode structured: reason resolved',
  decoded.codes[0] && decoded.codes[0].reason === 'response_sensitivity_exceeds_ceiling',
  decoded.codes[0] && decoded.codes[0].reason);
check('decode structured: tool resolved', decoded.codes[0] && decoded.codes[0].tool === 'mcp__demo__echo');

// 8. ApiClient enforces explicit per-plane sessionKind.
let ctorThrew = false;
try { new ApiClient({}); } catch { ctorThrew = true; }
check('ApiClient requires sessionKind', ctorThrew);

// 9. streamChat helper exists and exposes no per-chunk sanitize.
check('streamChat is a function', typeof streamChat === 'function');

// 10. TT policy name is the reconciled name.
check('TT policy name = yashigani-render', TT_POLICY_NAME === 'yashigani-render');

// Render verdict banner from structured fields (visual check).
const banner = document.createElement('ys-verdict-banner');
banner.verdict = decoded;
document.getElementById('banner').appendChild(banner);

// Render the markdown payload (inert) into a ys-markdown widget.
const md = document.createElement('ys-markdown');
md.content = payload1;
document.getElementById('md').appendChild(md);

function finalise() {
  // Give img onerror / async handlers a tick to (not) fire.
  setTimeout(() => {
    check('no XSS executed (window.__xss never called)', noXss(),
      window.__xssFired.join(','));
    const allPass = results.every((r) => r.pass);
    window.__CANARY_RESULT = { ok: allPass, results, xssFired: window.__xssFired };

    const out = document.getElementById('results');
    for (const r of results) {
      const row = document.createElement('div');
      row.className = r.pass ? 'pass' : 'fail';
      row.textContent = `${r.pass ? 'PASS' : 'FAIL'} — ${r.name}${r.pass ? '' : ' :: ' + r.detail}`;
      out.appendChild(row);
    }
    const summary = document.createElement('div');
    summary.className = allPass ? 'summary pass' : 'summary fail';
    summary.textContent = allPass
      ? `ALL ${results.length} CHECKS PASS — pipeline inert`
      : `FAILURES present (${results.filter((r) => !r.pass).length}/${results.length})`;
    out.prepend(summary);
    document.title = allPass ? 'CANARY OK' : 'CANARY FAIL';
  }, 200);
}
