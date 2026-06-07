"""#17 — unit tests for the client-policy sanity heuristic (OPA Phase 3a).

The pure `classify_results` heuristic is tested directly (no OPA/LLM I/O). The
sandbox/LLM/compile-repair async paths use the live OPA+ollama and are covered by
the e2e; here we pin the behavioural classification that gates a save.
"""
from yashigani.opa_assistant.sanity import classify_results, SEV_HIGH


def test_deny_all_flagged_high():
    # every benign sample denied -> deny_all HIGH
    results = [{"allow": False, "deny": ["x"]}, {"allow": False, "deny": ["x"]}, {"allow": False, "deny": ["x"]}]
    w = classify_results(undefined=False, results=results)
    codes = {x["code"] for x in w}
    assert "deny_all" in codes
    assert all(x["severity"] == SEV_HIGH for x in w if x["code"] == "deny_all")


def test_healthy_policy_no_warnings():
    # at least one allow -> no HIGH warnings
    results = [{"allow": True, "deny": []}, {"allow": False, "deny": ["scope"]}, {"allow": True, "deny": []}]
    w = classify_results(undefined=False, results=results)
    assert [x for x in w if x["severity"] == SEV_HIGH] == []


def test_undefined_flagged_high():
    # decision undefined for a sample -> contract-mismatch HIGH
    results = [{"allow": None, "deny": []}, {"allow": True, "deny": []}]
    w = classify_results(undefined=True, results=results)
    assert any(x["code"] == "decision_undefined" and x["severity"] == SEV_HIGH for x in w)


def test_empty_results_no_warnings():
    # PUT-only compile check (no samples) -> no behavioural warnings
    assert classify_results(undefined=False, results=[]) == []


def test_deny_all_not_double_flagged_as_never_allow():
    results = [{"allow": False, "deny": ["a"]}, {"allow": False, "deny": ["b"]}]
    codes = [x["code"] for x in classify_results(False, results)]
    assert codes.count("deny_all") == 1
    assert "never_allow" not in codes  # all-denied is deny_all, not never_allow
