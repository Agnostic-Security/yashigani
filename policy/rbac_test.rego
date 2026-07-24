# G4 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) — rbac.rego (OPA policy #8)
# had no dedicated test file. `yashigani_test.rego` DOES exercise `allow_rbac`
# transitively (via the top-level `allow`/`denials` decision), but ONLY through
# the wildcard shape `{"method": "*", "path_glob": "**"}` — every
# `test_rbac_*` case in yashigani_test.rego uses that same wildcard pattern
# (verified by grep: no other `path_glob`/`method` value appears in that
# file). rbac.rego's three OTHER matching branches — exact method match,
# exact path match, and the `/prefix/**` glob — and the RBAC-empty /
# blank-identity fail-open branches were UNEXERCISED anywhere. This file
# closes that gap with direct, by-name tests of `allow_rbac`,
# `_method_matches`, and `_path_matches`, plus rbac.rego's own
# self-describing `denials` contribution.
#
# Run with: opa test policy/
package yashigani_rbac_test

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# allow_rbac — direct exercise of the RBAC gate itself
# ---------------------------------------------------------------------------

test_allow_rbac_true_on_exact_method_and_path_match if {
	data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "GET", "path_glob": "/v1/chat"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/chat"},
		}
}

test_allow_rbac_true_on_prefix_glob_match if {
	data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "/v1/models/**"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/models/list"},
		}
}

test_allow_rbac_false_on_method_mismatch if {
	not data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "GET", "path_glob": "/v1/chat"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "POST", "path": "/v1/chat"},
		}
}

test_allow_rbac_false_on_path_not_under_prefix if {
	# "/v1/modelsx" must NOT match "/v1/models/**" (no slash boundary) —
	# proves _path_matches' prefix branch requires the literal "/" separator.
	not data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "/v1/models/**"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/modelsx"},
		}
}

test_allow_rbac_false_when_rbac_groups_empty if {
	not data.yashigani.allow_rbac with data.yashigani.rbac as {"groups": {}, "user_groups": {}}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/chat"},
		}
}

test_allow_rbac_false_when_identity_id_blank if {
	not data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "**"}]}},
		"user_groups": {"": ["eng"]},
	}
		with input as {
			"session": {"identity_id": ""},
			"request": {"method": "GET", "path": "/v1/chat"},
		}
}

test_allow_rbac_false_when_identity_not_in_any_group if {
	not data.yashigani.allow_rbac with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "**"}]}},
		"user_groups": {"idnt_someoneelse01": ["eng"]},
	}
		with input as {
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/chat"},
		}
}

# ---------------------------------------------------------------------------
# _method_matches — direct function-level exercise (by name)
# ---------------------------------------------------------------------------

test_method_matches_wildcard if {
	data.yashigani._method_matches("*", "DELETE")
}

test_method_matches_exact if {
	data.yashigani._method_matches("GET", "GET")
}

test_method_matches_rejects_mismatch if {
	not data.yashigani._method_matches("GET", "POST")
}

# ---------------------------------------------------------------------------
# _path_matches — direct function-level exercise (by name)
# ---------------------------------------------------------------------------

test_path_matches_double_wildcard if {
	data.yashigani._path_matches("**", "/anything/at/all")
}

test_path_matches_exact if {
	data.yashigani._path_matches("/v1/chat", "/v1/chat")
}

test_path_matches_rejects_different_exact_path if {
	not data.yashigani._path_matches("/v1/chat", "/v1/models")
}

test_path_matches_prefix_glob if {
	data.yashigani._path_matches("/v1/models/**", "/v1/models/list")
}

test_path_matches_prefix_glob_rejects_no_slash_boundary if {
	not data.yashigani._path_matches("/v1/models/**", "/v1/modelsx")
}

# ---------------------------------------------------------------------------
# rbac.rego's own self-describing `denials` contribution (#4 decision
# contract) — same package as yashigani.rego's `deny_rbac`/`_denied`.
# ---------------------------------------------------------------------------

test_rbac_denial_entry_present_when_rbac_denies if {
	ds := data.yashigani.denials with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "GET", "path_glob": "/v1/chat"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"principal": {"type": "human"},
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "POST", "path": "/v1/chat"},
			"method": "POST",
			"path": "/v1/chat",
		}
	some d in ds
	d.policy_id == "yashigani.rbac.group-permission"
}

test_no_rbac_denial_entry_when_rbac_permits if {
	ds := data.yashigani.denials with data.yashigani.rbac as {
		"groups": {"eng": {"allowed_resources": [{"method": "*", "path_glob": "**"}]}},
		"user_groups": {"idnt_abc123456789": ["eng"]},
	}
		with input as {
			"principal": {"type": "human"},
			"session": {"identity_id": "idnt_abc123456789"},
			"request": {"method": "GET", "path": "/v1/chat"},
			"method": "GET",
			"path": "/v1/chat",
		}
	not "yashigani.rbac.group-permission" in {d.policy_id | some d in ds}
}
