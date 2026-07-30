// Yashigani 4.0 shared layer — audited API client (spec §2).
//
// Single module centralising auth/session, error handling, output encoding, and
// the decision-code decode. Supersedes the 3.0 api()/apiMutate()/errMsg()/
// step-up cluster in dashboard.js (spec §2.5).
//
// Per-plane: ONE ApiClient instance per plane; never share across admin/user
// (RISK-100, spec §2.2). sessionKind is set at construction.

import { decodeVerdict } from './decode.js';
import { streamChat } from './sse.js';

const DEFAULT_READ_TIMEOUT_MS = 10000; // 3.0 dashboard.js:567-568

/** @typedef {{ok:boolean,status:number,data:any,error:({code:string,message:string}|null)}} Result */

/**
 * Normalise a FastAPI `detail` payload into {code, message} (spec §2.3). Port of
 * 3.0 errMsg() (dashboard.js:669-678). `message` is SERVER-AUTHORED and is
 * rendered as TRUSTED-CHROME via textContent — NEVER through the §3 pipeline.
 */
function normaliseError(status, payload) {
  let detail = payload;
  if (payload && typeof payload === 'object' && 'detail' in payload) {
    detail = payload.detail;
  }
  if (typeof detail === 'string') {
    return { code: String(status), message: detail };
  }
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    return {
      code: detail.error || detail.code || String(status),
      message: detail.message || detail.error || `HTTP ${status}`,
    };
  }
  if (Array.isArray(detail) && detail.length) {
    // Pydantic validation list.
    const first = detail[0] || {};
    const loc = Array.isArray(first.loc) ? first.loc.join('.') : '';
    return { code: 'validation_error', message: `${loc ? loc + ': ' : ''}${first.msg || 'invalid input'}` };
  }
  return { code: String(status), message: `HTTP ${status}` };
}

export class ApiClient {
  /**
   * @param {object} opts
   * @param {string} [opts.basePath='']           prefix prepended to paths
   * @param {'admin'|'user'} opts.sessionKind      plane selector (RISK-100)
   * @param {string} [opts.loginPath]              override 401 redirect target
   * @param {(spec:object)=>Promise<string|null>} [opts.onStepUp]  TOTP prompt;
   *        returns the 6-digit code, or null to cancel. Wired by ys-modal.
   */
  constructor({ basePath = '', sessionKind, loginPath, onStepUp } = {}) {
    if (sessionKind !== 'admin' && sessionKind !== 'user') {
      throw new Error("ApiClient requires sessionKind 'admin' | 'user'");
    }
    this.basePath = basePath;
    this.sessionKind = sessionKind;
    this.loginPath = loginPath || (sessionKind === 'admin' ? '/admin/login' : '/login');
    this._onStepUp = onStepUp || null;
  }

  _url(path) {
    return this.basePath + path;
  }

  _composeSignal(signal, timeoutMs) {
    const ctrl = new AbortController();
    let timer = null;
    if (timeoutMs) timer = setTimeout(() => ctrl.abort(), timeoutMs);
    if (signal) {
      if (signal.aborted) ctrl.abort();
      else signal.addEventListener('abort', () => ctrl.abort(), { once: true });
    }
    return { signal: ctrl.signal, clear: () => timer && clearTimeout(timer) };
  }

  /**
   * Read. On 401 → redirect to the plane's login. Returns parsed JSON or null
   * (matches 3.0 api() null-on-error contract; callers treat null as "no data").
   * @returns {Promise<any|null>}
   */
  async get(path, { signal } = {}) {
    const { signal: sig, clear } = this._composeSignal(signal, DEFAULT_READ_TIMEOUT_MS);
    try {
      const resp = await fetch(this._url(path), {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json', 'X-Yashigani-Plane': this.sessionKind },
        signal: sig,
      });
      if (resp.status === 401) {
        window.location.assign(this.loginPath);
        return null;
      }
      if (!resp.ok) return null;
      const ct = resp.headers.get('content-type') || '';
      return ct.includes('application/json') ? await resp.json() : null;
    } catch {
      return null;
    } finally {
      clear();
    }
  }

  /**
   * Write. Step-up aware (spec §2.6): on a `step_up_required` 401 the client
   * prompts for TOTP via onStepUp, posts /auth/stepup, then retries ONCE. The
   * client never decides which actions need step-up — it honours the server tag
   * (RISK-103). 403 is surfaced as an error (not nulled).
   * @returns {Promise<Result>}
   */
  async mutate(path, { method = 'POST', body, signal, _retried = false } = {}) {
    const { signal: sig, clear } = this._composeSignal(signal, null);
    try {
      const resp = await fetch(this._url(path), {
        method,
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Yashigani-Plane': this.sessionKind,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: sig,
      });

      let data = null;
      const ct = resp.headers.get('content-type') || '';
      if (ct.includes('application/json')) {
        try { data = await resp.json(); } catch { data = null; }
      }

      if (resp.ok) {
        return { ok: true, status: resp.status, data, error: null };
      }

      const err = normaliseError(resp.status, data);

      // Step-up interceptor (preserve 3.0 dashboard.js:614-640 behaviour).
      if (resp.status === 401 && err.code === 'step_up_required' && !_retried && this._onStepUp) {
        const code = await this._onStepUp(data && data.detail ? data.detail : data);
        if (!code) {
          return { ok: false, status: resp.status, data, error: { code: 'step_up_cancelled', message: 'Step-up cancelled.' } };
        }
        const stepup = await fetch(this._url('/auth/stepup'), {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-Yashigani-Plane': this.sessionKind },
          body: JSON.stringify({ totp_code: code }),
        });
        if (!stepup.ok) {
          return { ok: false, status: stepup.status, data: null, error: { code: 'step_up_failed', message: 'Step-up verification failed.' } };
        }
        return this.mutate(path, { method, body, signal, _retried: true });
      }

      if (resp.status === 401) {
        // Generic 401 / session expired → surface for the caller's toast/redirect.
        return { ok: false, status: 401, data, error: { code: err.code || 'session_expired_or_invalid', message: err.message } };
      }

      return { ok: false, status: resp.status, data, error: err };
    } catch (e) {
      return { ok: false, status: 0, data: null, error: { code: 'network_error', message: 'Network error.' } };
    } finally {
      clear();
    }
  }

  /**
   * Token-stream a chat completion (delegates to sse.js, §4). `onBlocked`
   * receives the STRUCTURED verdict tail of a pre-stream block (e.g. an HTTP
   * 403 returned before the SSE opened, RISK-105) so the caller can render the
   * trusted verdict banner instead of leaving the user with nothing.
   */
  stream(path, { body, headers, signal, onToken, onMessageDone, onBlocked, onError } = {}) {
    return streamChat(this._url(path), {
      body,
      headers: { 'X-Yashigani-Plane': this.sessionKind, ...(headers || {}) },
      signal,
      onToken,
      onMessageDone,
      onBlocked,
      onError,
    });
  }

  /**
   * Decode a STRUCTURED verdict field (delegates to decode.js, §2.4). Input is a
   * structured object only — never message text (RISK-105).
   */
  decode(structuredField) {
    return decodeVerdict(structuredField);
  }
}
