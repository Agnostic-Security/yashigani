"""#4 — unit tests for the unified user-alert envelope (yashigani.common.user_alert)."""
from yashigani.common.user_alert import (
    build_alert,
    alert_headers,
    valid_http_code,
    ACTION_BLOCKED,
    ACTION_REDACTED,
    ACTION_DENIED,
    DIRECTION_FROM_TOOL,
)


def test_build_alert_shape_and_required_fields():
    out = build_alert(ACTION_BLOCKED, "blocked because reasons")
    assert set(out.keys()) == {"yashigani_alert", "result"}
    assert out["result"] is None
    a = out["yashigani_alert"]
    assert a["action"] == ACTION_BLOCKED
    assert a["reason"] == "blocked because reasons"
    assert "timestamp" in a  # always stamped


def test_build_alert_optional_fields_included_when_present():
    a = build_alert(
        ACTION_DENIED, "nope", rule="R", direction=DIRECTION_FROM_TOOL,
        policy_id="yashigani.core.default-deny", request_id="req-1",
    )["yashigani_alert"]
    assert a["rule"] == "R"
    assert a["direction"] == DIRECTION_FROM_TOOL
    assert a["policy_id"] == "yashigani.core.default-deny"
    assert a["request_id"] == "req-1"


def test_build_alert_omits_absent_optionals():
    a = build_alert(ACTION_BLOCKED, "x")["yashigani_alert"]
    for k in ("rule", "direction", "policy_id", "request_id"):
        assert k not in a


def test_valid_http_code_clamps_to_rfc9110_range():
    assert valid_http_code(404) == 404
    assert valid_http_code(502) == 502
    assert valid_http_code(99) == 403       # below 1xx → default
    assert valid_http_code(600) == 403      # above 5xx → default
    assert valid_http_code("nan") == 403    # non-int → default
    assert valid_http_code(None, default=451) == 451


def test_alert_headers_form_and_latin1_safety():
    h = alert_headers(ACTION_REDACTED, rule="PII protection",
                      reason="masked sensitive data — café")
    assert h["X-Yashigani-Alert-Action"] == ACTION_REDACTED
    assert h["X-Yashigani-Alert-Rule"] == "PII protection"
    # header value must be ascii/latin-1 safe + single line
    h["X-Yashigani-Alert-Reason"].encode("latin-1")
    assert "\n" not in h["X-Yashigani-Alert-Reason"]


def test_alert_headers_strip_crlf_injection():
    # LAURA-2253-ALERT-001: BOTH \r and \n stripped from every header value
    # (response-splitting / header-injection defence), not just reason.
    h = alert_headers(
        "BLOCKED\r\nX-Injected: evil",
        rule="r\rule\n2",
        reason="line1\r\nline2\rmore",
    )
    for v in h.values():
        assert "\r" not in v and "\n" not in v
