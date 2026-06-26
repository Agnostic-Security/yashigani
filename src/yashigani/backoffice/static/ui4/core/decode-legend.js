// Yashigani 4.0 shared layer — decision-code legend, VENDORED AT BUILD (R6).
//
// Reconciliation R6: the legend is vendored at build time (CSP-clean, no runtime
// endpoint surface), NOT fetched from a server endpoint. This is the client
// mirror of the STABLE enumerations in:
//   - src/yashigani/gateway/decision_codes.py  (source of truth)
//   - docs/decision-code-legend.yml
//
// VERSION-SKEW GUARD (RISK-114): keep this file in lock-step with the two files
// above. The enumerations are STABLE (append-only, never renumber/reuse) so this
// vendored copy only ever GAINS entries. `schemaVersion` mirrors the YAML.
//
// This is structured data ONLY. It is consumed by decode.js to resolve coded
// tuples that arrive in STRUCTURED API fields — never to scan message text.

export const LEGEND = Object.freeze({
  schemaVersion: '1.0',
  format: '<tooluid>:<depth>:<status>:<leg>:<action>:<reason>',

  status: Object.freeze({
    0: 'blocked',
    1: 'ok',
  }),

  leg: Object.freeze({
    6: 'inspection', // ResponseInspection pipeline made the call
    7: 'ingress',    // OPA ingress leg (before the tool ran)
    8: 'egress',     // OPA egress leg (on the tool/model result)
    9: 'seed',       // seed-prompt / pre-flight adjudication
  }),

  action: Object.freeze({
    3: 'allow',
    7: 'deny',
    9: 'route-local',  // must be served by a local model (e.g. classified)
    0: 'redact',       // content removed (doc-OPA)
    6: 'pseudonymize', // content reversibly tokenised (doc-OPA)
  }),

  // reason / inspection code — non-sequential, STABLE. 99 = catch-all.
  reason: Object.freeze({
    0:  'clean',
    41: 'default_deny',
    63: 'client_policy_denied',
    28: 'identity_not_active',
    52: 'model_not_allocated',
    14: 'response_sensitivity_exceeds_ceiling',
    36: 'sensitivity_ceiling_exceeded',
    71: 'invalid_identity_ceiling',
    17: 'response_blocked_by_inspection',
    59: 'pii_detected',
    84: 'routing_unsafe_sensitive_to_cloud',
    47: 'provenance_cap',
    92: 'unknown_tool',
    33: 'unsupported_tool',
    68: 'injection_budget',
    25: 'sensitivity_exceeds_egress_ceiling',
    76: 'classified_requires_local',
    88: 'pci_data_present',
    99: 'unmapped',
  }),

  // Human-readable one-liners for the verdict banner (TRUSTED-CHROME).
  reasonLabel: Object.freeze({
    0:  'No restriction applied.',
    41: 'Blocked by a default-deny policy.',
    63: 'Blocked by a policy bound to your account.',
    28: 'Your account is inactive or disabled.',
    52: 'You are not allocated the requested model.',
    14: 'The response contained data above your clearance.',
    36: 'Your request contained data above your clearance.',
    71: 'Your account clearance is missing or invalid.',
    17: 'A security inspection blocked the result (possible injection or data exfiltration).',
    59: 'Personal data was present and cannot be sent to this provider.',
    84: 'Sensitive content would have been routed to a cloud model.',
    47: 'A provenance or hop-budget limit refused the call.',
    92: 'The requested tool is not in the approved catalogue.',
    33: 'The tool or operation is not supported.',
    68: 'A per-hop injection budget was exhausted.',
    25: 'An egress data-classification ceiling was exceeded.',
    76: 'Classified content must use a local model only.',
    88: 'Cardholder (PCI) data was present.',
    99: 'Restricted (see support for details).',
  }),

  // Known tool uids (resolve <tooluid> → name). Extend per deployment; an
  // unknown uid is safe to show and decodes to "<uid XXXX>".
  knownTools: Object.freeze({
    '64F7': 'mcp__demo__echo',
  }),
});
