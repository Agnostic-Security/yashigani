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
#       BLOCK  >  REDACT  >  ROUTE_LOCAL  >  PSEUDONYMIZE  >  LOG
#
#   ROUTE_LOCAL (PART 2 / Laura D1, field-role routing): the matrix asked for
#   PSEUDONYMIZE on a CLOUD-bound (mode-B) egress, but a matched value is an
#   OPERATE_ON sensitive field (a currency amount, DOB, IBAN/PAN the cloud model
#   would compute on / validate).  An opaque token in place of such a value makes
#   the cloud model HALLUCINATE a plausible value and reason over the invention —
#   a correctness AND a confidentiality problem.  So instead of blobbing it to the
#   cloud we route the WHOLE document to the LOCAL model (the original values stay
#   in-estate, no broken blob).  It sits ABOVE PSEUDONYMIZE (overrides a
#   cloud-bound pseudonymize) and BELOW REDACT/BLOCK (a configured permanent
#   removal or a hold still wins — the operate-on value is gone / held either way).
#   This is the OPA-side mirror of the pipeline's field-role seam
#   (documents/pipeline.py _pseudonymize PART 2): OPA decides, the Python seam is
#   the fail-closed backstop when OPA is unreachable.
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
#                                             location: "<kind>:<loc>:span=a-b",
#                                             field_role: "REFERENCE_ONLY"|
#                                                         "OPERATE_ON" }
#                                           field_role (PART 2 / field_role.py):
#                                           OPERATE_ON = the model computes on /
#                                           validates the value; an opaque blob
#                                           makes the cloud hallucinate.  Drives
#                                           the ROUTE_LOCAL decision below.
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
#                                             pseudonymize_mode, small_set_escalation,
#                                             policy_id, user_message, code }
#                                         The last three are the operator-supplied
#                                         self-describing fields (may be "").  When
#                                         non-empty they override the built-in values
#                                         in the decision (IRIS-DOC-META).
#   data.yashigani.document.config.detokenize_role       RBAC role for de-tokenize / table
#   data.yashigani.document.config.map_ttl_seconds       fail-closed TTL for the replacer map
#   data.yashigani.document.config.small_set_threshold   record_count at/under which QI gate fires
#
# Self-describing contract (Tiago, unified user-alert): every decision carries
# policy_id + user_message + code so the layman alert and audit event are
# uniform across 100+ policies.  user_message NEVER contains cleartext.

package yashigani.document

import rego.v1

# ---------------------------------------------------------------------------
# Self-describing policy identity — IRIS-DOC-META operator-supplied override.
#
# When the winning matrix row carries a non-empty operator-supplied policy_id /
# user_message / code (pushed via to_opa_document()), the decision surfaces
# THOSE values so the layman alert and audit event reflect the operator's
# intent.  When those fields are absent or empty the built-in action-derived
# values apply (fail-safe: a malformed/missing field NEVER breaks evaluation).
#
# _winning_policy: the applicable policy whose action equals the FINAL action,
# i.e. the row that *drove* the actual disposition (matrix action AND final
# action agree — no fail-closed override redirected the outcome).
# There may be multiple rows with the same action (e.g. two PSEUDONYMIZE rows
# for different class scopes that both matched); any one will do because they
# share the same action — the first one found is used.
# Undefined when:
#   - the final action was forced by a fail-closed override (e.g. BLOCK due to
#     incomplete extraction — _strongest_configured was PSEUDONYMIZE but the
#     system blocked it; in that case action != _strongest_configured)
#   - LOG with no matches (no applicable policies)
# In those cases _op_* are undefined and built-in values apply cleanly.
# ---------------------------------------------------------------------------
_winning_policy := p if {
	some p in _applicable_policies
	p.action == _strongest_configured
	# The final action must equal the matrix action: if a fail-closed override
	# changed action to BLOCK while _strongest_configured was PSEUDONYMIZE, this
	# guard fails and _winning_policy is correctly undefined.
	action == _strongest_configured
}

# Operator field helpers — each is defined only when the field is non-empty.
# "Non-empty" means the string exists AND is not the empty string "".
# Fail-safe: object.get returns "" (the default) if the key is absent.
_op_policy_id := v if {
	v := object.get(_winning_policy, "policy_id", "")
	v != ""
}

_op_user_message := v if {
	v := object.get(_winning_policy, "user_message", "")
	v != ""
}

_op_code := v if {
	v := object.get(_winning_policy, "code", "")
	v != ""
}

# --- Self-describing policy identity -----------------------------------------
# Operator-supplied value wins when present; built-in is the fallback.
policy_id := _op_policy_id

default policy_id := "DOC-ENFORCE-001"

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
# PART 2 (Laura D1) field-role routing — ROUTE_LOCAL gate.
# A match is OPERATE_ON *sensitive* when field_role == "OPERATE_ON" AND its class
# is one the cloud would compute on / validate as a confidentiality concern, not a
# mere format check.  Mirrors documents/field_role.py is_operate_on_sensitive:
# the known operate-on-but-non-sensitive classes (PHONE, DATE) are excluded; an
# unknown OPERATE_ON class is fail-safe SENSITIVE (do not blob to the cloud).
# ---------------------------------------------------------------------------
_operate_on_nonsensitive_classes := {"PHONE", "DATE"}

# Bare class name (drop the PII./PCI. namespace, upper-case) — mirrors _bare().
_bare_class(data_class) := upper(c) if {
	parts := split(data_class, ".")
	c := parts[count(parts) - 1]
}

_operate_on_sensitive(m) if {
	m.field_role == "OPERATE_ON"
	not _operate_on_nonsensitive_classes[_bare_class(m.data_class)]
}

# At least one detected match is an operate-on sensitive field.
_has_operate_on_sensitive if {
	some m in _matches
	_operate_on_sensitive(m)
}

# Mode B is the definite CLOUD round-trip (mode A keeps the join under the user's
# local control — see pipeline _pseudonymize PART 2).  We mirror the pipeline's
# trigger exactly: the seam fires on mode B only.
_cloud_bound if _mode == "B"

# ROUTE_LOCAL fires when the MATRIX asked for PSEUDONYMIZE, the egress is
# cloud-bound (mode B), and an operate-on sensitive field is present.  This is the
# field-role override of a cloud-bound pseudonymize: route the whole document to
# the LOCAL model instead of blobbing a value the cloud would hallucinate over.
_route_local_escalation if {
	_strongest_configured == "PSEUDONYMIZE"
	_cloud_bound
	_has_operate_on_sensitive
}

# ---------------------------------------------------------------------------
# Strongest-action precedence: BLOCK > REDACT > ROUTE_LOCAL > PSEUDONYMIZE > LOG.
# _strongest_configured is the strongest action the MATRIX asked for (before the
# fail-closed overrides + the ROUTE_LOCAL field-role escalation); _action folds in
# the overrides.  ROUTE_LOCAL is not a matrix action — it is an escalation of a
# cloud-bound PSEUDONYMIZE — so it is not in the matrix-candidate ranking; it is
# applied as an override in `action` below, ranked between REDACT and PSEUDONYMIZE.
# ---------------------------------------------------------------------------
_rank := {"LOG": 1, "PSEUDONYMIZE": 2, "ROUTE_LOCAL": 3, "REDACT": 4, "BLOCK": 5}

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

# PART 2 field-role override: a cloud-bound PSEUDONYMIZE carrying an operate-on
# sensitive field is escalated to ROUTE_LOCAL (route the whole document to the
# LOCAL model rather than blob a value the cloud would hallucinate over).  This
# beats PSEUDONYMIZE but is below REDACT/BLOCK — because the escalation requires
# _strongest_configured == "PSEUDONYMIZE" (REDACT/BLOCK rank higher, so they win
# the matrix before this rule is even eligible).  Gated by the same
# fully-inspectable / policed / no-F2 invariants, but NOT by re-render support:
# ROUTE_LOCAL forwards the ORIGINAL bytes to the local model (no re-render), so it
# is well-defined even on a format that cannot be re-rendered (mirrors the Python
# seam, which fires before any re-render is attempted).
action := "ROUTE_LOCAL" if {
	_extraction_complete
	count(_matches) > 0
	not _unpoliced_match
	not _reid_escalation
	_route_local_escalation
}

# Configured action wins when the document is fully inspectable, every matched
# class is policed, the chosen re-render is supported, no F2 escalation, and the
# PART 2 field-role escalation did not fire.
action := _strongest_configured if {
	_extraction_complete
	count(_matches) > 0
	not _unpoliced_match
	not _reid_escalation
	_action_supported(_strongest_configured)
	not _route_local_escalation
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
	# ROUTE_LOCAL needs no re-render (it forwards the ORIGINAL bytes to the local
	# model), so an unsupported re-render format must NOT BLOCK a route-local
	# escalation — the field-role override wins (and keeps the doc in-estate).
	not _route_local_escalation
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

# ROUTE_LOCAL allows the document — it is forwarded (untransformed, original
# bytes) to the LOCAL model, not blocked.  The obligation below pins the local
# route so the gateway never sends it cloud-bound.
allow if action == "ROUTE_LOCAL"

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

# ROUTE_LOCAL: pin the whole document + its agent call to the LOCAL model (the
# original values never leave the estate, so they need no tokenisation; an opaque
# blob bound for the cloud would make the cloud model hallucinate).  Mirrors the
# pipeline _route_local disposition (forward original bytes to the local route).
obligations contains "route_document_to_local_model" if action == "ROUTE_LOCAL"

obligations contains "audit_document_decision"

# ---------------------------------------------------------------------------
# Self-describing code + layman user_message (never contains cleartext).
#
# IRIS-DOC-META: when the winning matrix row carries a non-empty operator-
# supplied code/user_message, that value is used.  Otherwise the built-in
# action-derived value applies.  The guard `not _op_code` / `not _op_user_message`
# ensures exactly one definition is true (fail-safe for rego.v1 completeness).
# user_message NEVER contains cleartext — operator-supplied messages are static
# strings; interpolation with detected values is not permitted.
# ---------------------------------------------------------------------------

# --- Operator-supplied override (IRIS-DOC-META) ---
code := _op_code if _op_code

user_message := _op_user_message if _op_user_message

# --- Built-in action-derived fallbacks (active when no operator override) ---
code := "DOCUMENT_PII_PSEUDONYMIZED" if {
	action == "PSEUDONYMIZE"
	not _op_code
}

code := "DOCUMENT_REDACTED" if {
	action == "REDACT"
	not _op_code
}

code := "DOCUMENT_LOGGED" if {
	action == "LOG"
	not _op_code
}

code := "DOCUMENT_BLOCKED" if {
	action == "BLOCK"
	not _op_code
}

code := "DOCUMENT_ROUTED_LOCAL" if {
	action == "ROUTE_LOCAL"
	not _op_code
}

user_message := msg if {
	action == "PSEUDONYMIZE"
	not _op_user_message
	msg := sprintf(
		"We replaced %d piece(s) of identifying information in your %s file with placeholders before it left your environment. You have a private table to turn the placeholders back into the real values yourself.",
		[count(_pseudo_matches), _format],
	)
}

user_message := sprintf(
	"We permanently removed %d piece(s) of identifying information from your %s file (including any hidden parts and metadata) before it left your environment.",
	[count(_matches), _format],
) if {
	action == "REDACT"
	not _op_user_message
}

user_message := "This file was allowed through; any identifying information in it has been recorded for audit." if {
	action == "LOG"
	not _op_user_message
}

user_message := "This file still contained enough identifying detail to re-identify people even after placeholders were applied, so it was blocked from leaving your environment." if {
	action == "BLOCK"
	_reid_escalation
	not _op_user_message
}

user_message := "This file could not be safely cleared for its content, so it was blocked from leaving your environment." if {
	action == "BLOCK"
	not _reid_escalation
	not _op_user_message
}

# ROUTE_LOCAL: the file carries values the cloud model would compute on (amounts,
# dates of birth, account numbers) — a placeholder there would make the cloud
# invent a wrong value, so the whole file was handled by the on-site model
# instead and never left your environment.
user_message := "This file contained values that the external AI would need to calculate with (such as amounts, dates of birth or account numbers). Replacing those with placeholders would make the external AI guess wrong values, so the whole file was handled by the on-site model and never left your environment." if {
	action == "ROUTE_LOCAL"
	not _op_user_message
}

# The operate-on sensitive data classes that forced the ROUTE_LOCAL decision
# (audit / layman-alert breadcrumb — class names only, never values; mirrors the
# pipeline result's operate_on_classes).  Empty for every other action.
operate_on_classes := {m.data_class | some m in _matches; _operate_on_sensitive(m)} if action == "ROUTE_LOCAL"

default operate_on_classes := set()

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
	# PART 2 field-role routing breadcrumb (class names only — never values).
	"operate_on_classes": operate_on_classes,
	# replacer-map custody (opaque handle ONLY — never the map itself; F5).
	"replacer_map_handle": object.get(object.get(input, "document", {}), "reid_handle", ""),
	"replacer_map_ttl": _map_ttl,
	"detokenize_rbac_role": _detok_role,
}
