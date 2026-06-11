# EXAMPLE / ILLUSTRATIVE — EU AI Act gating for an AI gateway.
# (Reg. (EU) 2024/1689: Art 5 prohibited practices, Art 14 human oversight, Art 50 transparency.)
# Generic starter — classify the use case upstream, then gate on it here.
#
# Decision document:  data.clients.aiact.decision = {allow, deny, obligations}
#
# === CUSTOMIZE ===
#   input.ai_use.risk_class           "minimal" | "limited" | "high" | "unacceptable"
#   input.ai_use.human_oversight      bool — a human is in/over the loop (Art 14)
#   input.ai_use.transparency_notice  bool — user told they interact with AI (Art 50)
package clients.aiact

import rego.v1

default _rc := ""

_rc := input.ai_use.risk_class

default _oversight := false

_oversight if input.ai_use.human_oversight == true

default _transparency := false

_transparency if input.ai_use.transparency_notice == true

# Art 5 — prohibited AI practices are blocked outright.
deny contains "prohibited_ai_practice" if _rc == "unacceptable"

# Art 14 — high-risk systems require human oversight.
deny contains "high_risk_without_human_oversight" if {
	_rc == "high"
	not _oversight
}

# Art 50 — limited/high-risk systems require a transparency notice.
deny contains "missing_transparency_notice" if {
	_rc in {"limited", "high"}
	not _transparency
}

# Fail-closed: an unclassified use case cannot be permitted.
deny contains "ai_risk_class_missing" if _rc == ""

default allow := false

allow if count(deny) == 0

obligations contains "log_high_risk_decision" if _rc == "high"

# Yashigani decision contract — user-facing alert fields (policy_id / user_message / code).
policy_id := "clients.aiact.eu-ai-act"
user_message := "Blocked under the EU AI Act policy: this looks like a prohibited practice, or a high-risk use without the required human oversight / transparency notice."
code := 403
decision := {"allow": allow, "deny": deny, "obligations": obligations, "policy_id": policy_id, "user_message": user_message, "code": code}
