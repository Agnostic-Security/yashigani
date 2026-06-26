// Yashigani 4.0 shared layer — decision-code-legend decoder (spec §2.4, RISK-105
// / FIND-AVA-001 — HARD CONTRACT).
//
// Client mirror of `decode_step()` (gateway/decision_codes.py:142-170). The
// legend (decode-legend.js) is the vendored-at-build single source (R6).
//
// HARD CONTRACT: this module operates ONLY on STRUCTURED API response fields
// (response.decision_codes[], response.user_alert). It NEVER scans LLM/agent
// message text for a coded tuple or for the [BLOCKED BY YASHIGANI] sentinel.
// `decodeVerdict()`'s input TYPE is a structured object — passing a raw string
// is a TypeError, making the misuse a type error, not a discipline lapse.

import { LEGEND } from './decode-legend.js';

/** @typedef {{code,tool,tool_uid,depth,status,leg,action,reason,reasonLabel,blocked}} DecodedStep */

function _num(x) {
  const n = Number.parseInt(x, 10);
  return Number.isNaN(n) ? null : n;
}

/**
 * Decode ONE coded tuple string taken from the STRUCTURED decision_codes[]
 * field. The tuple is a fixed 6-field contract — this is NOT free-text parsing;
 * the caller must have obtained `code` from a structured API field.
 *
 * Internal: not exported. Callers use decodeVerdict() on the structured object.
 * @param {string} code "<tooluid>:<depth>:<status>:<leg>:<action>:<reason>"
 * @returns {DecodedStep}
 */
function decodeStep(code) {
  const raw = String(code == null ? '' : code).trim();
  const parts = raw.split(':');
  if (parts.length !== 6) {
    return { code: raw, error: `expected 6 fields, got ${parts.length}` };
  }
  const [uid, depth, status, leg, action, reason] = parts;
  const s = _num(status);
  const lg = _num(leg);
  const ac = _num(action);
  const rs = _num(reason);
  const uidUpper = (uid || '').toUpperCase();
  return {
    code: raw,
    tool: LEGEND.knownTools[uidUpper] || `<uid ${uid}>`,
    tool_uid: uidUpper,
    depth: _num(depth),
    status: LEGEND.status[s] ?? `<status ${status}>`,
    leg: LEGEND.leg[lg] ?? `<leg ${leg}>`,
    action: LEGEND.action[ac] ?? `<action ${action}>`,
    reason: LEGEND.reason[rs] ?? `<reason ${reason}>`,
    reasonLabel: LEGEND.reasonLabel[rs] ?? 'Restricted (see support for details).',
    blocked: s === 0,
  };
}

/**
 * Decode a STRUCTURED verdict object into the typed shape consumed by
 * ys-verdict-banner (spec §5.1). Input MUST be a structured object — NOT a
 * string. Passing a string throws (RISK-105 enforcement: no free-text path).
 *
 * @param {{decision_codes?: string[], user_alert?: object, blocked?: boolean,
 *          sentinel?: boolean}} structured  structured API field(s) only
 * @returns {{sentinel: boolean, codes: DecodedStep[], userMessage: string|null,
 *            policyId: string|null}}
 */
export function decodeVerdict(structured) {
  if (typeof structured === 'string') {
    // HARD CONTRACT: never decode from free text (message blobs). The sentinel
    // and codes come only from server-set structured fields.
    throw new TypeError(
      'decodeVerdict requires a structured object (decision_codes[]/user_alert), ' +
      'never a message string (RISK-105).',
    );
  }
  if (structured == null || typeof structured !== 'object') {
    return { sentinel: false, codes: [], userMessage: null, policyId: null };
  }

  const codesIn = Array.isArray(structured.decision_codes)
    ? structured.decision_codes
    : [];
  const codes = codesIn.map(decodeStep);

  const alert = (structured.user_alert && typeof structured.user_alert === 'object')
    ? structured.user_alert
    : {};

  // The [BLOCKED BY YASHIGANI] sentinel renders ONLY when the server set a
  // structured boolean — never by string-matching text (FIND-AVA-001.2).
  const sentinel = structured.sentinel === true
    || structured.blocked === true
    || codes.some((c) => c.blocked === true);

  return {
    sentinel,
    codes,
    userMessage: alert.user_message ?? alert.message ?? null,
    policyId: alert.policy_id ?? alert.code ?? null,
  };
}
