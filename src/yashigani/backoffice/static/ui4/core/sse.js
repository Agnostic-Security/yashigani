// Yashigani 4.0 shared layer — SSE / streaming helper (spec §4).
//
// Token streaming for chat over the gateway's OpenAI-compatible SSE. Uses
// fetch() + ReadableStream (not EventSource — we need POST + auth +
// credentials:'same-origin'; EventSource is GET-only).
//
// RISK-106: this helper NEVER sanitises or parses per token. It accumulates the
// COMPLETE message and hands the full string to the consumer's onMessageDone
// for a single renderMarkdown() (spec §3.2). There is NO per-chunk sanitize
// path here or anywhere in the layer.
//
// RISK-105: a mid-stream block arrives as a STRUCTURED event, routed to
// onMessageDone(fullText, structuredTail). The stream text is NEVER scanned for
// [BLOCKED BY YASHIGANI] (spec §4.2).
//
// RISK-105 (pre-stream): when the gateway/OPA blocks BEFORE the SSE opens it
// returns an HTTP error (e.g. 403) and no stream is ever established, so the
// out-of-band block event above never fires. We read the error body for the
// SAME structured verdict fields and route them to onBlocked(structuredTail).
// Only the structured fields are surfaced — server-authored free text
// (error.message / detail strings) is NEVER promoted to the verdict banner
// (anti-spoofing). A 403 with no structured fields yields a generic
// {blocked:true} tail so the trusted "request blocked" chrome still renders.

const DEFAULT_IDLE_MS = 60000; // idle-token timeout; streams are long-lived (§4.1)

/**
 * Extract the STRUCTURED verdict tail from a pre-stream error body (RISK-105).
 * Recognises ONLY the structured contract fields — decision_codes / user_alert
 * / blocked / yashigani — at the top level or nested under FastAPI `detail`.
 * Free text (error.message, detail strings) is deliberately ignored: it must
 * never reach trusted chrome. A pre-stream 403 always yields blocked:true so a
 * generic banner renders even when the body carries no structured fields.
 *
 * @param {number} status   HTTP status of the failed pre-stream response
 * @param {any} body        parsed JSON body (or null)
 * @returns {{decision_codes?:string[], user_alert?:object, blocked?:boolean}}
 */
function blockTailFromBody(status, body) {
  const tail = {};
  const sources = [];
  if (body && typeof body === 'object') {
    sources.push(body);
    if (body.detail && typeof body.detail === 'object') sources.push(body.detail);
  }
  for (const src of sources) {
    if (src.yashigani && typeof src.yashigani === 'object') Object.assign(tail, src.yashigani);
    if (Array.isArray(src.decision_codes)) tail.decision_codes = src.decision_codes;
    if (src.user_alert && typeof src.user_alert === 'object') tail.user_alert = src.user_alert;
    if (typeof src.blocked === 'boolean') tail.blocked = src.blocked;
  }
  // A pre-stream 403 ALWAYS surfaces the blocked banner (generic if no fields).
  if (status === 403) tail.blocked = true;
  return tail;
}

/**
 * Stream a chat completion.
 *
 * @param {string} path  same-origin endpoint (e.g. /v1/chat/completions)
 * @param {object} opts
 * @param {object} opts.body            JSON request body (stream:true is forced)
 * @param {object} [opts.headers]       extra request headers
 * @param {AbortSignal} [opts.signal]   caller abort signal (composes internally)
 * @param {number} [opts.idleMs]        idle-token timeout (ms)
 * @param {(delta:string)=>void} opts.onToken        per-token raw delta
 * @param {(full:string, tail:object|null)=>void} opts.onMessageDone  once, on complete
 * @param {(tail:object)=>void} [opts.onBlocked]     pre-stream block (RISK-105):
 *        structured verdict tail from an HTTP error body (e.g. 403) when the
 *        SSE never opened. Fires INSTEAD of onError for blocks.
 * @param {(err:Error)=>void} [opts.onError]
 * @returns {{cancel: ()=>void}}
 */
export function streamChat(path, opts) {
  const {
    body,
    headers = {},
    signal,
    idleMs = DEFAULT_IDLE_MS,
    onToken = () => {},
    onMessageDone = () => {},
    onBlocked = () => {},
    onError = () => {},
  } = opts || {};

  const controller = new AbortController();
  let idleTimer = null;
  let done = false;

  const cancel = () => {
    if (!done) {
      done = true;
      if (idleTimer) clearTimeout(idleTimer);
      controller.abort();
    }
  };

  if (signal) {
    if (signal.aborted) cancel();
    else signal.addEventListener('abort', cancel, { once: true });
  }

  const armIdle = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      if (!done) {
        done = true;
        controller.abort();
        onError(new Error('stream idle timeout'));
      }
    }, idleMs);
  };

  (async () => {
    let accumulated = '';
    let structuredTail = null;
    try {
      const resp = await fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream', ...headers },
        body: JSON.stringify({ ...(body || {}), stream: true }),
        signal: controller.signal,
      });
      if (!resp.ok) {
        // Pre-stream block (RISK-105): the gateway/OPA rejected the request
        // before the SSE opened, so the mid-stream structured event never
        // arrives. Read the structured verdict tail from the error body and
        // route it to onBlocked (the verdict banner) — NEVER the free-text
        // error message. Non-block errors still raise via onError.
        let errBody = null;
        const ect = resp.headers.get('content-type') || '';
        if (ect.includes('application/json')) {
          try { errBody = await resp.json(); } catch { errBody = null; }
        }
        const tail = blockTailFromBody(resp.status, errBody);
        if (resp.status === 403 || tail.blocked === true
            || tail.decision_codes || tail.user_alert) {
          if (!done) {
            done = true;
            if (idleTimer) clearTimeout(idleTimer);
            onBlocked(tail);
          }
          return;
        }
        throw new Error(`stream HTTP ${resp.status}`);
      }
      if (!resp.body) {
        throw new Error(`stream HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';
      armIdle();

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { value, done: streamDone } = await reader.read();
        if (streamDone) break;
        armIdle();
        buffer += decoder.decode(value, { stream: true });

        // Parse complete SSE frames (separated by blank line).
        let sep;
        // eslint-disable-next-line no-cond-assign
        while ((sep = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          for (const line of frame.split('\n')) {
            const trimmed = line.startsWith('data:') ? line.slice(5).trimStart() : null;
            if (trimmed == null) continue;
            if (trimmed === '[DONE]') {
              continue; // terminal sentinel; loop will end on stream close
            }
            let evt;
            try {
              evt = JSON.parse(trimmed);
            } catch {
              continue; // ignore non-JSON keep-alives
            }
            // OpenAI-compatible delta.
            const delta = evt?.choices?.[0]?.delta?.content;
            if (typeof delta === 'string' && delta.length) {
              accumulated += delta;
              onToken(delta); // consumer shows via textContent ONLY (RISK-106)
            }
            // Structured out-of-band tail: decision_codes / user_alert / block
            // event (RISK-105). NEVER parsed out of message text.
            if (evt && (evt.decision_codes || evt.user_alert || evt.blocked || evt.yashigani)) {
              structuredTail = {
                ...(structuredTail || {}),
                ...(evt.yashigani || {}),
                ...(evt.decision_codes ? { decision_codes: evt.decision_codes } : {}),
                ...(evt.user_alert ? { user_alert: evt.user_alert } : {}),
                ...(evt.blocked != null ? { blocked: evt.blocked } : {}),
              };
            }
          }
        }
      }

      if (!done) {
        done = true;
        if (idleTimer) clearTimeout(idleTimer);
        onMessageDone(accumulated, structuredTail);
      }
    } catch (err) {
      if (idleTimer) clearTimeout(idleTimer);
      if (done && err && err.name === 'AbortError') return; // expected on cancel
      done = true;
      onError(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  return { cancel };
}
