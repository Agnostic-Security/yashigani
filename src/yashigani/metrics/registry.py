"""
Yashigani Metrics — Central Prometheus metric definitions (v0.7.1).

All metrics are defined once here and imported wherever they are updated.
Using the default prometheus_client registry so generate_latest() works
without extra wiring.

Metric naming convention: yashigani_<subsystem>_<name>_<unit>
"""
from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, REGISTRY
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

    # Stubs so the rest of the codebase imports cleanly even without prometheus_client
    class _Noop:
        def __init__(self, *a, **kw): pass
        def labels(self, **kw): return self
        def inc(self, *a): pass
        def set(self, *a): pass
        def observe(self, *a): pass
        def time(self): return _NoopCtx()
    class _NoopCtx:
        def __enter__(self): return self
        def __exit__(self, *a): pass
    # Conditional-import fallback: re-bind the public names to the no-op
    # placeholders so callers can construct metrics even without the package
    # installed. mypy sees the union of types between branches and flags the
    # rebind; the runtime behaviour is intentional.
    Counter = Gauge = Histogram = _Noop  # type: ignore[misc,assignment]
    REGISTRY = None  # type: ignore[assignment]


def _C(name, doc, labelnames=()):
    return Counter(name, doc, labelnames) if _AVAILABLE else Counter(name, doc, labelnames)

def _G(name, doc, labelnames=()):
    return Gauge(name, doc, labelnames) if _AVAILABLE else Gauge(name, doc, labelnames)

def _H(name, doc, labelnames=(), buckets=None):
    kwargs = {"buckets": buckets} if buckets else {}
    return Histogram(name, doc, labelnames, **kwargs) if _AVAILABLE else Histogram(name, doc, labelnames)


# ---------------------------------------------------------------------------
# Gateway metrics
# ---------------------------------------------------------------------------

gateway_requests_total = _C(
    "yashigani_gateway_requests_total",
    "Total gateway requests by method, action, and agent.",
    ["method", "action", "agent_id"],
)

gateway_request_duration_seconds = _H(
    "yashigani_gateway_request_duration_seconds",
    "Gateway request latency in seconds.",
    ["method", "action", "agent_id"],
    buckets=[.005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0],
)

gateway_upstream_status_total = _C(
    "yashigani_gateway_upstream_status_total",
    "Upstream HTTP response status codes.",
    ["status_code"],
)

gateway_request_body_bytes = _H(
    "yashigani_gateway_request_body_bytes",
    "Request body size in bytes.",
    ["agent_id"],
    buckets=[64, 512, 4096, 32768, 262144, 1048576, 4194304],
)

# ---------------------------------------------------------------------------
# Inspection pipeline metrics
# ---------------------------------------------------------------------------

inspection_classifications_total = _C(
    "yashigani_inspection_classifications_total",
    "Inspection classifications by label and severity.",
    ["label", "severity"],
)

inspection_duration_seconds = _H(
    "yashigani_inspection_duration_seconds",
    "Inspection pipeline latency (classify + sanitise).",
    ["agent_id"],
    buckets=[.01, .05, .1, .25, .5, 1.0, 2.5, 5.0, 10.0],
)

inspection_sanitizations_total = _C(
    "yashigani_inspection_sanitizations_total",
    "Sanitization outcomes for CREDENTIAL_EXFIL detections.",
    ["outcome"],   # sanitized | discarded
)

inspection_threshold = _G(
    "yashigani_inspection_threshold",
    "Current sanitization confidence threshold (0.70–0.99).",
)

inspection_model = _G(
    "yashigani_inspection_model_info",
    "Currently active Ollama classifier model (label only).",
    ["model"],
)

# ---------------------------------------------------------------------------
# Rate limiter metrics
# ---------------------------------------------------------------------------

ratelimit_violations_total = _C(
    "yashigani_ratelimit_violations_total",
    "Rate limit violations by dimension.",
    ["dimension"],  # global | ip | agent | session
)

ratelimit_multiplier = _G(
    "yashigani_ratelimit_adaptive_multiplier",
    "Current RPI-derived rate limit multiplier (0.25–1.0).",
)

ratelimit_effective_rps = _G(
    "yashigani_ratelimit_effective_rps",
    "Effective requests-per-second per dimension after adaptive scaling.",
    ["dimension"],  # global | ip | agent | session
)

ratelimit_config_last_updated_timestamp = _G(
    "yashigani_ratelimit_config_last_updated_timestamp_seconds",
    "Unix timestamp of the last rate limit configuration update.",
)

# ---------------------------------------------------------------------------
# Resource pressure / CHS metrics
# ---------------------------------------------------------------------------

resource_pressure_index = _G(
    "yashigani_resource_pressure_index",
    "Composite Resource Pressure Index (0.0–1.0).",
)

resource_memory_pressure = _G(
    "yashigani_resource_memory_pressure",
    "Memory pressure ratio (used/limit) from cgroup v2.",
)

resource_cpu_throttle = _G(
    "yashigani_resource_cpu_throttle",
    "CPU throttle ratio from cgroup v2 cpu.stat.",
)

resource_gpu_pressure = _G(
    "yashigani_resource_gpu_pressure",
    "GPU composite pressure (0.6×util + 0.4×vram).",
)

resource_gpu_utilisation = _G(
    "yashigani_resource_gpu_utilisation",
    "GPU compute utilisation per device (0.0–1.0).",
    ["device_index", "device_name", "backend"],
)

resource_gpu_memory_pressure = _G(
    "yashigani_resource_gpu_memory_pressure",
    "GPU VRAM pressure per device (used/total, 0.0–1.0).",
    ["device_index", "device_name", "backend"],
)

resource_memory_used_bytes = _G(
    "yashigani_resource_memory_used_bytes",
    "Container memory usage in bytes.",
)

chs_handles_active = _G(
    "yashigani_chs_handles_active",
    "Currently active (non-expired, non-revoked) CHS handles.",
)

chs_handles_issued_total = _C(
    "yashigani_chs_handles_issued_total",
    "Total CHS handles issued since startup.",
)

chs_handles_expired_total = _C(
    "yashigani_chs_handles_expired_total",
    "Total CHS handles expired (TTL elapsed).",
)

chs_handles_revoked_total = _C(
    "yashigani_chs_handles_revoked_total",
    "Total CHS handles explicitly revoked.",
)

chs_current_ttl_seconds = _G(
    "yashigani_chs_current_ttl_seconds",
    "Current TTL (seconds) for newly issued CHS handles.",
)

# ---------------------------------------------------------------------------
# KSM metrics
# ---------------------------------------------------------------------------

kms_rotations_total = _C(
    "yashigani_kms_rotations_total",
    "KSM rotation attempts by outcome and type.",
    ["outcome", "rotation_type"],  # outcome: success|failure|critical; type: scheduled|manual
)

kms_rotation_last_success_timestamp = _G(
    "yashigani_kms_rotation_last_success_timestamp_seconds",
    "Unix timestamp of the last successful KSM rotation.",
)

# ---------------------------------------------------------------------------
# Auth / admin metrics
# ---------------------------------------------------------------------------

hibp_check_api_unavailable_total = _C(
    "yashigani_hibp_check_api_unavailable_total",
    "HIBP breach-check API calls that failed (network error / timeout / 5xx). "
    "Password change proceeded (fail-open). Alert if sustained over time — "
    "may indicate loss of outbound HTTPS access on the edge network.",
)

auth_login_attempts_total = _C(
    "yashigani_auth_login_attempts_total",
    "Admin login attempts by outcome.",
    ["outcome"],  # success | failure
)

auth_totp_failures_total = _C(
    "yashigani_auth_totp_failures_total",
    "TOTP verification failures (backoff events).",
    ["account_tier"],
)

auth_lockouts_total = _C(
    "yashigani_auth_lockouts_total",
    "Account lockouts (5th failure threshold reached).",
    ["account_tier"],
)

auth_active_sessions = _G(
    "yashigani_auth_active_sessions",
    "Currently valid admin sessions in the session store.",
)

# ---------------------------------------------------------------------------
# Audit metrics
# ---------------------------------------------------------------------------

audit_events_total = _C(
    "yashigani_audit_events_total",
    "Audit events written to the volume sink by event type.",
    ["event_type"],
)

audit_siem_deliveries_total = _C(
    "yashigani_audit_siem_deliveries_total",
    "SIEM forwarding attempts by outcome and target.",
    ["outcome", "target_name"],  # outcome: success | failure
)


# ---------------------------------------------------------------------------
# RBAC metrics
# ---------------------------------------------------------------------------

rbac_groups_total = _G(
    "yashigani_rbac_groups_total",
    "Total RBAC groups currently configured.",
)

rbac_policy_push_total = _C(
    "yashigani_rbac_policy_push_total",
    "OPA RBAC data push attempts by outcome.",
    ["outcome"],  # success | failure
)


# ---------------------------------------------------------------------------
# Agent metrics
# ---------------------------------------------------------------------------

agent_auth_failures_total = _C(
    "yashigani_agent_auth_failures_total",
    "Agent authentication failures by reason.",
    ["reason"],
)

agent_calls_total = _C(
    "yashigani_agent_calls_total",
    "Agent-to-agent call attempts by caller, target, and outcome.",
    ["caller_agent_id", "target_agent_id", "outcome"],
)

agent_call_duration_seconds = _H(
    "yashigani_agent_call_duration_seconds",
    "Agent-to-agent call duration in seconds.",
    ["caller_agent_id", "target_agent_id"],
    buckets=[.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5],
)

agent_registry_size = _G(
    "yashigani_agent_registry_size",
    "Number of registered agents by status.",
    ["status"],
)

# ---------------------------------------------------------------------------
# Inspection backend metrics
# ---------------------------------------------------------------------------

inspection_backend_requests_total = _C(
    "yashigani_inspection_backend_requests_total",
    "Inspection backend classification requests by backend and outcome.",
    ["backend", "outcome"],
)

inspection_backend_latency_seconds = _H(
    "yashigani_inspection_backend_latency_seconds",
    "Inspection backend classification latency in seconds.",
    ["backend"],
    buckets=[.05, .1, .25, .5, 1, 2.5, 5, 10, 15, 30],
)

inspection_backend_fallbacks_total = _C(
    "yashigani_inspection_backend_fallbacks_total",
    "Backend fallback transitions by failed and next backend.",
    ["failed_backend", "next_backend"],
)

inspection_backend_exhausted_total = _C(
    "yashigani_inspection_backend_exhausted_total",
    "No backends available; fail-closed triggered.",
)

inspection_active_backend = _G(
    "yashigani_inspection_active_backend",
    "Currently active inspection backend (label only).",
    ["backend"],
)


# ---------------------------------------------------------------------------
# CI/CD metrics (pushed via Prometheus Pushgateway by CI jobs)
# ---------------------------------------------------------------------------

cicd_trivy_high_cve_count = _G(
    "yashigani_trivy_high_cve_count",
    "Number of HIGH+CRITICAL CVEs found by Trivy per image.",
    ["image"],
)

cicd_test_coverage_percent = _G(
    "yashigani_test_coverage_percent",
    "Test coverage percentage from last CI run.",
)

cicd_security_scan_failures_total = _C(
    "yashigani_security_scan_failures_total",
    "Total scheduled security scan failures since last restart.",
)

cicd_last_build_success_timestamp = _G(
    "yashigani_ci_last_build_success_timestamp_seconds",
    "Unix timestamp of last successful CI build.",
)

cicd_image_signature_valid = _G(
    "yashigani_image_signature_valid",
    "1 if the deployed image has a valid Cosign signature, 0 otherwise.",
    ["image"],
)

cicd_image_sbom_present = _G(
    "yashigani_image_sbom_present",
    "1 if the deployed image has an SBOM attestation, 0 otherwise.",
    ["image"],
)


# ---------------------------------------------------------------------------
# v0.5.0 — PostgreSQL / audit queue / SIEM metrics
# ---------------------------------------------------------------------------

repeated_small_calls_total = _C(
    "yashigani_repeated_small_calls_total",
    "Cumulative REPEATED_SMALL_CALLS anomaly events fired.",
    ["tenant_id"],
)

inference_payload_log_queue_depth = _G(
    "yashigani_inference_payload_log_queue_depth",
    "Current depth of the async inference payload write queue.",
)

cache_hits_total = _C(
    "yashigani_cache_hits_total",
    "Response cache hits.",
    ["tenant_id"],
)

cache_misses_total = _C(
    "yashigani_cache_misses_total",
    "Response cache misses.",
    ["tenant_id"],
)

cache_evictions_total = _C(
    "yashigani_cache_evictions_total",
    "Response cache keys evicted (TTL + manual).",
    ["tenant_id"],
)

jwt_validations_total = _C(
    "yashigani_jwt_validations_total",
    "JWT introspection outcomes.",
    ["result"],  # valid | invalid | expired | fetch_error
)

jwks_cache_hits_total = _C(
    "yashigani_jwks_cache_hits_total",
    "JWKS cache hit by layer.",
    ["layer"],  # memory | redis
)

fasttext_classifications_total = _C(
    "yashigani_fasttext_classifications_total",
    "FastText first-pass classification outcomes.",
    ["result"],  # clean | unsafe | uncertain
)

fasttext_latency_ms = _H(
    "yashigani_fasttext_latency_ms",
    "FastText inference latency in milliseconds.",
    buckets=[0.5, 1, 2, 5, 10, 20, 50],
)

trace_spans_total = _C(
    "yashigani_trace_spans_total",
    "OTLP spans emitted.",
    ["span_name", "status"],
)

db_pool_acquired_total = _C(
    "yashigani_db_pool_acquired_total",
    "Postgres pool acquisitions.",
    ["service"],
)

db_pool_waittime_seconds = _H(
    "yashigani_db_pool_waittime_seconds",
    "Time waiting for a Postgres pool connection.",
    buckets=[.001, .005, .01, .05, .1, .25, .5, 1.0],
)

audit_queue_overflow_total = _C(
    "yashigani_audit_queue_overflow_total",
    "Audit events dropped due to full queue.",
)

siem_forward_errors_total = _C(
    "yashigani_siem_forward_errors_total",
    "SIEM forwarding failures.",
    ["siem"],  # splunk | elasticsearch | wazuh
)

# ---------------------------------------------------------------------------
# v0.9.0 — SIEM async queue metrics (SC-04)
# ---------------------------------------------------------------------------

siem_queue_depth = _G(
    "yashigani_siem_queue_depth",
    "Current depth of the Redis-backed SIEM delivery queue per sink.",
    ["sink"],
)

siem_dlq_depth = _G(
    "yashigani_siem_dlq_depth",
    "Current depth of the SIEM dead-letter queue (DLQ) per sink.",
    ["sink"],
)

# ---------------------------------------------------------------------------
# v0.9.0 — Audit chain integrity (F-12)
# ---------------------------------------------------------------------------

audit_chain_breaks_total = _G(
    "yashigani_audit_chain_breaks_total",
    "Total number of audit log hash-chain breaks detected by audit_verify.py. "
    "Updated by the offline verification script via Prometheus Pushgateway.",
)

endpoint_ratelimit_violations_total = _C(
    "yashigani_endpoint_ratelimit_violations_total",
    "Per-endpoint rate limit violations.",
    ["endpoint_hash"],
)

# ── v0.7.0 — DB partition monitoring ────────────────────────────────────────

# Updated by scripts/partition_maintenance.py
audit_partition_missing = _G(
    "yashigani_audit_partition_missing",
    "1 if the upcoming month's audit_events partition is missing; 0 if all present. "
    "Alert fires when this is 1 — run scripts/partition_maintenance.py immediately.",
)


# ---------------------------------------------------------------------------
# v2.0 — Routing, budget, sensitivity, pool metrics (P1-P5 alert targets)
# ---------------------------------------------------------------------------

# OPA routing safety net
yashigani_opa_safety_blocks_total = Counter(
    "yashigani_opa_safety_blocks_total",
    "OPA routing safety net blocks — sensitive data heading to cloud",
)

# Sensitivity classification
yashigani_sensitivity_detections_total = Counter(
    "yashigani_sensitivity_detections_total",
    "Sensitivity detections by classification level",
    ["level"],
)

yashigani_sensitivity_conflicts_total = Counter(
    "yashigani_sensitivity_conflicts_total",
    "Sensitivity classification conflicts between scanner layers",
)

yashigani_sensitivity_ceiling_breaches_total = Counter(
    "yashigani_sensitivity_ceiling_breaches_total",
    "Identity accessed data above their sensitivity ceiling",
)

# Routing decisions
yashigani_routing_decisions_total = Counter(
    "yashigani_routing_decisions_total",
    "Optimization Engine routing decisions by rule and route",
    ["rule", "route"],
)

yashigani_oe_decision_duration_seconds = Histogram(
    "yashigani_oe_decision_duration_seconds",
    "Optimization Engine decision latency",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1],
)

# Budget
yashigani_budget_tokens_total = Counter(
    "yashigani_budget_tokens_total",
    "Cloud tokens consumed by provider and identity kind",
    ["provider", "kind", "route"],
)

yashigani_budget_exhausted_total = Counter(
    "yashigani_budget_exhausted_total",
    "Budget exhaustion events — identity auto-switched to local",
)

yashigani_budget_utilisation_pct = Gauge(
    "yashigani_budget_utilisation_pct",
    "Budget utilisation percentage by identity",
    ["identity_id"],
)

# Pool Manager
yashigani_pool_containers_active = Gauge(
    "yashigani_pool_containers_active",
    "Currently active managed containers",
)

yashigani_pool_containers_created_total = Counter(
    "yashigani_pool_containers_created_total",
    "Containers created by Pool Manager",
)

yashigani_pool_containers_replaced_total = Counter(
    "yashigani_pool_containers_replaced_total",
    "Containers replaced due to health failures",
)

yashigani_pool_containers_idle_teardown_total = Counter(
    "yashigani_pool_containers_idle_teardown_total",
    "Containers torn down due to idle timeout",
)

yashigani_pool_scale_failures_total = Counter(
    "yashigani_pool_scale_failures_total",
    "Failed scaling attempts — resources exhausted",
)

yashigani_pool_postmortems_total = Counter(
    "yashigani_pool_postmortems_total",
    "Postmortem forensic reports collected",
)

yashigani_pool_limit_exceeded_total = Counter(
    "yashigani_pool_limit_exceeded_total",
    "Container creation blocked by license tier limit",
)


def get_metrics() -> dict:
    """Return a flat dict of all metric objects — useful for testing."""
    return {k: v for k, v in globals().items() if not k.startswith("_") and k not in (
        "Counter", "Gauge", "Histogram", "CollectorRegistry", "REGISTRY",
        "annotations", "get_metrics",
    )}
