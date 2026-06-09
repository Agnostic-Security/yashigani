# Yashigani — Document-content enforcement policy (2.26).
#
# PRODUCTION rego the gateway evaluates for the document-content feature.
# Promoted from the illustrative demo contract
# (AgnosticSecurity/DemoOPAs/examples/document_pseudonymize.rego, plan §4.2 / §9 B9):
# the demo proved the PSEUDONYMIZE-specific output shape; this module is the
# committed, matrix-driven decision the gateway loads in its policy bundle.
#
# DECISION MODEL (plan §5.0 / §5.3):
#   The operator configures a policy MATRIX (data_class × format × route → action)
#   in the backoffice; it is persisted to Redis (documents/policy_store.py) and
#   pushed here as data.yashigani.document.policies[].  For each detected
#   DataMatch the gateway hands us, every policy whose (data_class, format, route)
#   matches contributes a candidate action.  The document disposition is the
#   STRONGEST candidate action under the precedence:
#
#       BLOCK  >  REDACT  >  PSEUDONYMIZE  >  LOG
#
#   Fail-closed (plan §6.1, NON-NEGOTIABLE):
#     - extraction_complete == false             → BLOCK (uninspectable parts)
#     - a matched class with NO configured policy → BLOCK (no policy = no clearance)
#     - PSEUDONYMIZE/REDACT on an unsupported format → BLOCK (cannot re-render)
#     - small-set / residual-QI re-identification     → BLOCK (F2 escalation)
#     - no input at all / malformed                    → BLOCK (default action)
#
# === INPUT (gateway extraction + classification front-end, plan §4.2 / datamatch.py) ===
#   input.document.format                 "xlsx"|"docx"|"pptx"|"pdf"|"csv"|"txt"
#   input.document.extraction_complete    bool — matches=[] is trustworthy ONLY when true
#   input.document.segment_kinds[]        provenance kinds present (incl. "METADATA")
#   input.document.matches[]              DataMatch[] (datamatch.py as_opa_match), each:
#                                           { data_class: "PII.EMAIL"|... ,
#                                             qi: bool, instance: <MASKED>,
#                                             location: "<kind>:<loc>:span=a-b" }
#   input.document.record_count           int — population size (small-set gate, F2)
#   input.document.reid_handle            string — UNGUESSABLE capability token (F5)
#   input.document.pseudonymize_supported bool — format re-renders coherently this version
#   input.document.redaction_supported    bool — format re-renders coherently this version
#   input.routing_decision.route          "ingress-upload"|"egress-mcp-result"|
#                                         "json-attachment"|... (matched against policy.route)
#   input.request.pseudonymize_mode       "A" (give-the-user-the-table, DEFAULT) | "B"
#
# === DATA (documents/policy_store.py → push_document_data) ===
#   data.yashigani.document.policies[]    the operator's action matrix, each:
#                                           { data_class, format, route, action,
#                                             pseudonymize_mode, small_set_escalation }
#   data.yashigani.document.config.detokenize_role       RBAC role for de-tokenize / table
#   data.yashigani.document.config.map_ttl_seconds       fail-closed TTL for the replacer map
#   data.yashigani.document.config.small_set_threshold   record_count at/under which QI gate fires
#
# Self-describing contract (Tiago, unified user-alert): every decision carries
# policy_id + user_message + code so the layman alert and audit event are
# uniform across 100+ policies.  user_message NEVER contains cleartext.

package yashigani.document

import rego.v1

# --- Self-describing policy identity -----------------------------------------
policy_id := "DOC-ENFORCE-001"

# --- Config with fail-closed defaults (override via data bundle) --------------
default _detok_role := "doc-pseudonymize-reverser"

_detok_role := r if {
	r := data.yashigani.document.config.detokenize_role
	r != ""
}

# Fail-closed: never "unbounded".  Short bounded default.
default _map_ttl := 300

_map_ttl := t if {
	t := data.yashigani.document.config.map_ttl_seconds
	t > 0
}

# F2 small-set escalation threshold; conservative fail-closed default.
default _small_set_threshold := 20

_small_set_threshold := s if {
	s := data.yashigani.document.config.small_set_threshold
	s > 0
}

# Mode A (give-the-user-the-table) is the default when the request pins no mode.
_mode := object.get(object.get(input, "request", {}), "pseudonymize_mode", "A")

_format := object.get(object.get(input, "document", {}), "format", "")

_route := object.get(object.get(input, "routing_decision", {}), "route", "any")

_matches := object.get(object.get(input, "document", {}), "matches", [])

_record_count := object.get(object.get(input, "document", {}), "record_count", 0)

_extraction_complete := object.get(object.get(input, "document", {}), "extraction_complete", false)

_pseudonymize_supported := object.get(object.get(input, "document", {}), "pseudonymize_supported", false)

_redaction_supported := object.get(object.get(input, "document", {}), "redaction_supported", false)

# ---------------------------------------------------------------------------
# Policy matching — data_class × format × route → action
# ---------------------------------------------------------------------------
# A policy matches a DataMatch when its data_class matches (exact, or the
# namespace prefix: a policy data_class "PII" matches a match "PII.EMAIL"),
# its format is "any" or equals the document format, and its route is "any"
# or equals the routing decision.

_class_matches(policy_class, match_class) if policy_class == match_class

_class_matches(policy_class, match_class) if {
	# Namespace prefix: policy "PII" matches match "PII.EMAIL".
	startswith(match_class, concat("", [policy_class, "."]))
}

_format_matches(policy_format) if policy_format == "any"

_format_matches(policy_format) if policy_format == _format

_route_matches(policy_route) if policy_route == "any"

_route_matches(policy_route) if policy_route == _route

# The set of policies that apply to at least one detected match.
_applicable_policies contains p if {
	some p in data.yashigani.document.policies
	_format_matches(p.format)
	_route_matches(p.route)
	some m in _matches
	_class_matches(p.data_class, m.data_class)
}

# Candidate actions contributed by applicable policies.
_candidate_actions contains a if {
	some p in _applicable_policies
	a := p.action
}

# ---------------------------------------------------------------------------
# Fail-closed: a matched class with NO applicable policy has no clearance.
# (No policy configured for a detected sensitive class ⇒ BLOCK, never silent pass.)
# ---------------------------------------------------------------------------
_unpoliced_match if {
	some m in _matches
	not _match_is_policed(m)
}

_match_is_policed(m) if {
	some p in _applicable_policies
	_class_matches(p.data_class, m.data_class)
}

# ---------------------------------------------------------------------------
# F2 residual quasi-identifier / small-set re-identification gate.
# A QI match remaining un-tokenized on a small record set is re-identifiable by
# inference.  When the strongest configured action is PSEUDONYMIZE (the rows
# would ship as tokens) AND the set is small AND a QI survives, escalate.
# ---------------------------------------------------------------------------
_small_set if {
	_record_count > 0
	_record_count <= _small_set_threshold
}

_has_qi_match if {
	some m in _matches
	m.qi == true
}

# Whether ANY applicable policy for QI matches opted into small_set_escalation.
_small_set_escalation_enabled if {
	some p in _applicable_policies
	p.small_set_escalation == true
}

_reid_escalation if {
	_strongest_configured == "PSEUDONYMIZE"
	_small_set
	_has_qi_match
	_small_set_escalation_enabled
}

# ---------------------------------------------------------------------------
# Strongest-action precedence: BLOCK > REDACT > PSEUDONYMIZE > LOG.
# _strongest_configured is the strongest action the MATRIX asked for (before the
# fail-closed overrides); _action folds in the overrides.
# ---------------------------------------------------------------------------
_rank := {"LOG": 1, "PSEUDONYMIZE": 2, "REDACT": 3, "BLOCK": 4}

default _strongest_configured := "LOG"

_strongest_configured := act if {
	count(_candidate_actions) > 0
	ranks := [_rank[a] | some a in _candidate_actions]
	max_rank := max(ranks)
	some a in _candidate_actions
	_rank[a] == max_rank
	act := a
}

# ---------------------------------------------------------------------------
# The document-level disposition (plan §5.0).  Default BLOCK (fail-closed, F9).
# ---------------------------------------------------------------------------
default action := "BLOCK"

# Clean pass-through: extraction complete AND nothing matched ⇒ LOG.
action := "LOG" if {
	_extraction_complete
	count(_matches) == 0
}

# Configured action wins when the document is fully inspectable, every matched
# class is policed, the chosen re-render is supported, and no F2 escalation.
action := _strongest_configured if {
	_extraction_complete
	count(_matches) > 0
	not _unpoliced_match
	not _reid_escalation
	_action_supported(_strongest_configured)
}

# --- Fail-closed overrides (each forces BLOCK) -------------------------------
action := "BLOCK" if not _extraction_complete

action := "BLOCK" if {
	_extraction_complete
	count(_matches) > 0
	_unpoliced_match
}

action := "BLOCK" if _reid_escalation

action := "BLOCK" if {
	_extraction_complete
	count(_matches) > 0
	not _unpoliced_match
	not _reid_escalation
	not _action_supported(_strongest_configured)
}

# A re-rendering action is "supported" only when the format can carry it.
_action_supported("LOG")
_action_supported("BLOCK")
_action_supported("PSEUDONYMIZE") if _pseudonymize_supported
_action_supported("REDACT") if _redaction_supported

# ---------------------------------------------------------------------------
# PSEUDONYMIZE per-match token assignment (consistent, type-tagged).
# Engine keys on value for true coherence; this example derives a stable token
# from (data_class, location) so the policy output is reproducible.
# ---------------------------------------------------------------------------
_pseudo_matches := [m | some m in _matches; _match_is_policed(m)]

_token_for(m) := tok if {
	some i, mm in _pseudo_matches
	mm.location == m.location
	mm.data_class == m.data_class
	tok := sprintf("%s_%d", [lower(replace(m.data_class, ".", "_")), i + 1])
}

per_match_actions := [out |
	some m in _pseudo_matches
	out := {
		"data_class": m.data_class,
		"location": m.location,
		"action": action,
		"token": _token_for(m),
	}
] if action == "PSEUDONYMIZE"

default per_match_actions := []

# ---------------------------------------------------------------------------
# Allow / deny — shared gateway contract (default-deny).
# allow == true means "forward (possibly transformed) document"; false ⇒ BLOCK-fallback.
# ---------------------------------------------------------------------------
default allow := false

allow if action == "LOG"

allow if action == "PSEUDONYMIZE"

allow if action == "REDACT"

deny contains "extraction_incomplete" if not _extraction_complete

deny contains "unpoliced_sensitive_class" if {
	_extraction_complete
	count(_matches) > 0
	_unpoliced_match
}

deny contains "reidentifiable_small_set" if _reid_escalation

deny contains "unsupported_format_for_action" if {
	_extraction_complete
	count(_matches) > 0
	not _unpoliced_match
	not _reid_escalation
	not _action_supported(_strongest_configured)
}

# ---------------------------------------------------------------------------
# Obligations the gateway MUST perform (plan §5.3).
# ---------------------------------------------------------------------------
obligations contains "apply_pseudonymize_tokens" if action == "PSEUDONYMIZE"

obligations contains "deliver_correspondence_table_rbac" if {
	action == "PSEUDONYMIZE"
	_mode == "A"
}

obligations contains "vault_replacer_map_round_trip" if {
	action == "PSEUDONYMIZE"
	_mode == "B"
}

obligations contains "bind_restore_to_egress_positions" if {
	action == "PSEUDONYMIZE"
	_mode == "B"
}

obligations contains "strip_hidden_and_metadata" if action == "REDACT"

obligations contains "audit_document_decision"

# ---------------------------------------------------------------------------
# Self-describing code + layman user_message (never contains cleartext).
# ---------------------------------------------------------------------------
code := "DOCUMENT_PII_PSEUDONYMIZED" if action == "PSEUDONYMIZE"

code := "DOCUMENT_REDACTED" if action == "REDACT"

code := "DOCUMENT_LOGGED" if action == "LOG"

code := "DOCUMENT_BLOCKED" if action == "BLOCK"

user_message := msg if {
	action == "PSEUDONYMIZE"
	msg := sprintf(
		"We replaced %d piece(s) of identifying information in your %s file with placeholders before it left your environment. You have a private table to turn the placeholders back into the real values yourself.",
		[count(_pseudo_matches), _format],
	)
}

user_message := sprintf(
	"We permanently removed %d piece(s) of identifying information from your %s file (including any hidden parts and metadata) before it left your environment.",
	[count(_matches), _format],
) if action == "REDACT"

user_message := "This file was allowed through; any identifying information in it has been recorded for audit." if action == "LOG"

user_message := "This file still contained enough identifying detail to re-identify people even after placeholders were applied, so it was blocked from leaving your environment." if {
	action == "BLOCK"
	_reid_escalation
}

user_message := "This file could not be safely cleared for its content, so it was blocked from leaving your environment." if {
	action == "BLOCK"
	not _reid_escalation
}

# ---------------------------------------------------------------------------
# The decision document — shared {allow, deny, obligations} at the top so the
# gateway integrates it uniformly; the rest is document-action output (plan §4.2).
# ---------------------------------------------------------------------------
decision := {
	"allow": allow,
	"deny": deny,
	"obligations": obligations,
	# self-describing fields (carried to audit + layman alert)
	"policy_id": policy_id,
	"code": code,
	"user_message": user_message,
	# document-action outputs
	"action": action,
	"pseudonymize_mode": _mode,
	"per_match_actions": per_match_actions,
	"matched_classes": {m.data_class | some m in _matches},
	# replacer-map custody (opaque handle ONLY — never the map itself; F5).
	"replacer_map_handle": object.get(object.get(input, "document", {}), "reid_handle", ""),
	"replacer_map_ttl": _map_ttl,
	"detokenize_rbac_role": _detok_role,
}
