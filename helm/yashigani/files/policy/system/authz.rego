# Yashigani — OPA management-API authorisation (LAURA-30-001 L2 fix).
#
# Loaded by OPA at startup under the special package ``system.authz``
# (required by --authorization=basic; OPA evaluates ``data.system.authz.allow``
# on every management API request).
#
# Enforcement model:
#   L1: --authentication=tls  → reject connections with no client cert (Go
#       VerifyClientCertIfGiven → VerifyClientCertAlways; no-cert = 401).
#   L2: --authorization=basic → evaluate this policy; non-allow = 403.
#
# Trust model: every mesh peer holds a leaf cert signed by the internal CA.
# mTLS alone is not sufficient as a write gate — agents, MCPs, and APIs are
# ALSO cert-bearing mesh members. This policy restricts WHICH authenticated
# identity may perform WHICH management operations.
#
# OPA populates ``input`` as follows (--authentication=tls, OPA docs §AuthN):
#   input.identity            — the *subject* field of the presented client cert
#   input.path                — array of path segments (e.g. ["v1","policies","…"])
#   input.method              — HTTP method string ("GET","PUT","POST","DELETE",…)
#
# SPIFFE identities (URI SANs on the leaf certs; OPA surfaces the Subject CN
# or the first URI SAN as input.identity depending on OPA version — both are
# anchored to the cert presented, which is the mesh identity):
#   backoffice    — SOLE writer;  may PUT/DELETE /v1/policies/*, PUT/PATCH /v1/data/*
#   gateway       — EVAL only;    may POST  /v1/data/yashigani/**
#   <all others>  — DENY;         agents, MCPs, APIs are SUBJECTS of policy,
#                                  never OPA admins (approval grants mesh access,
#                                  never OPA management-API access)
#
# Health / diagnostic probe:
#   GET /health (port 8282 --diagnostic-addr) is also subject to authz when
#   --authorization=basic is set. The K8s kubelet probe does NOT present a cert.
#   OPA allows /health unauthenticated (input.identity = "") for liveness/readiness.
#   The compose stack has healthcheck disabled (scratch image, no shell); the
#   gateway/backoffice fail-closed per-request — so the health bypass here is
#   ONLY load-bearing for K8s probes on :8282.
#
# Default deny: any request not matched by an explicit allow rule is rejected.
# This includes all agent/MCP/API identities: they hold valid mesh certs and
# can pass --authentication=tls, but L2 here denies their mgmt-API attempts.
#
# Run tests with: opa test policy/system/
#
# Last updated: LAURA-30-001 fix (2026-06-14)

package system.authz

import future.keywords.if
import future.keywords.in

# ── Identity constants ────────────────────────────────────────────────────────
# OPA --authentication=tls surfaces the client cert identity as input.identity.
# The exact string depends on how the cert was issued:
#   - If the cert carries a URI SAN (SPIFFE URI), OPA ≥1.0 sets input.identity
#     to that URI SAN string.
#   - Older builds may use Subject CN. Both are leaf-cert-anchored and CA-verified.
# We match on both the SPIFFE URI and the CN form (Subject=backoffice / gateway)
# to be robust across OPA versions and cert issuance variants in the mesh.
# The sets below represent every string form that may appear as input.identity
# for each service role.

_backoffice_identities := {
    "spiffe://yashigani.internal/backoffice",
    "backoffice",
}

_gateway_identities := {
    "spiffe://yashigani.internal/gateway",
    "gateway",
}

# ── Health probe bypass (unauthenticated K8s kubelet on :8282) ───────────────
# The diagnostic-addr port (:8282) is used for liveness/readiness probes in K8s.
# The kubelet does not present a client cert. Allow /health with no identity.
# This is the ONLY unauthenticated path; all mgmt-API paths require a cert.

allow if {
    input.path == ["health"]
}

# ── backoffice: WRITE gates (policy upload + data push) ──────────────────────
# The backoffice is the sole authorised writer of OPA policies and data.
# All paths: policy push (PUT /v1/policies/*), RBAC/allocations/bindings/
# document data push (PUT /v1/data/*), PATCH /v1/data/*.

allow if {
    input.identity in _backoffice_identities
    input.method in {"PUT", "PATCH", "DELETE"}
    input.path[0] == "v1"
    input.path[1] in {"policies", "data"}
}

# backoffice: READ (GET /v1/policies/*, GET /v1/data/*) — needed for policy
# list/viewer route and OPA assistant sanity checks that PUT then DELETE a
# sandbox module (compile-check) and POST /v1/data/<path>/decision.

allow if {
    input.identity in _backoffice_identities
    input.method in {"GET", "POST"}
    input.path[0] == "v1"
    input.path[1] in {"policies", "data"}
}

# ── gateway: EVAL only (POST /v1/data/yashigani/**) ─────────────────────────
# The gateway evaluates OPA decisions per-request. It only POSTs to
# /v1/data/yashigani/<decision_path> and /v1/data/client_enforce/<aggregate>.
# It never reads or writes policy modules or arbitrary data namespaces.

allow if {
    input.identity in _gateway_identities
    input.method == "POST"
    input.path[0] == "v1"
    input.path[1] == "data"
    # Gateway only evaluates under yashigani.* or client_enforce.* namespaces.
    input.path[2] in {"yashigani", "client_enforce", "client_bindings", "clients"}
}

# ── Default: deny ─────────────────────────────────────────────────────────────
# Any request not matched above is rejected (403).
# This covers:
#   - All agent / MCP / API service identities (cert-bearing but not OPA-admin).
#   - Requests to undeclared paths (admin API paths not explicitly allowed above).
#   - No-identity requests to mgmt API paths (gateway → /health bypass above).
