"""
Deterministic gate suite — DocumentPolicyStore (2.26 productionised policy layer).

Mode: DETERMINISTIC GATE. Runs against fakeredis — no live Redis required.

Coverage:
  DPS-01  seed_defaults() seeds the demo matrix on an empty namespace
  DPS-02  seed_defaults() is idempotent (no clobber of operator policies)
  DPS-03  add_policy() write-through + fresh monotonic id
  DPS-04  add_policy() rejects out-of-vocab rows (fail-closed validation)
  DPS-05  remove_policy() write-through; returns existence
  DPS-06  persistence: a fresh store over the SAME redis replays state
  DPS-07  to_opa_document() shape matches what policy/document.rego consumes
  DPS-08  config get/set write-through + replay

Author: Tom. Last updated: 2026-06-09.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.documents.policy_store import DocumentPolicyStore


@pytest.fixture
def redis_client():
    return fakeredis.FakeStrictRedis()


def test_dps_01_seed_defaults(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    policies = store.list_policies()
    # 4 ready-to-use example policies (PII-1/2, PCI-1/2) + 1 baseline LOG row.
    assert len(policies) == 5
    actions = {p["action"] for p in policies}
    assert actions == {"PSEUDONYMIZE", "REDACT", "LOG"}


def test_dps_01b_four_examples_available_and_self_describing(redis_client):
    """The four example OPAs are seeded as AVAILABLE policies and are
    self-describing (policy_id + layman user_message + code) — exactly what the
    admin UI lists as selectable, ready-to-use examples."""
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    examples = [p for p in store.list_policies() if p.get("example")]
    assert len(examples) == 4
    by_pid = {p["policy_id"]: p for p in examples}
    assert set(by_pid) == {"DOC-EX-PII-1", "DOC-EX-PII-2", "DOC-EX-PCI-1", "DOC-EX-PCI-2"}
    # Explicit data-class → action mapping.
    assert (by_pid["DOC-EX-PII-1"]["data_class"], by_pid["DOC-EX-PII-1"]["action"]) == ("PII", "PSEUDONYMIZE")
    assert (by_pid["DOC-EX-PII-2"]["data_class"], by_pid["DOC-EX-PII-2"]["action"]) == ("PII", "REDACT")
    assert (by_pid["DOC-EX-PCI-1"]["data_class"], by_pid["DOC-EX-PCI-1"]["action"]) == ("PCI", "PSEUDONYMIZE")
    assert (by_pid["DOC-EX-PCI-2"]["data_class"], by_pid["DOC-EX-PCI-2"]["action"]) == ("PCI", "REDACT")
    # Self-describing: every example carries a name + layman message + code.
    for p in examples:
        assert p["name"] and p["user_message"] and p["code"]


def test_dps_02_seed_idempotent(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    added = store.add_policy(
        data_class="SECRET", format="any", route="any", action="BLOCK",
        description="operator rule",
    )
    # Re-seeding must NOT clobber the operator's rule.
    store.seed_defaults()
    ids = {p["id"] for p in store.list_policies()}
    assert added["id"] in ids
    # 5 seeded defaults + 1 operator rule.
    assert len(store.list_policies()) == 6


def test_dps_03_add_write_through_fresh_id(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    p1 = store.add_policy(data_class="PHI", format="pdf", route="any", action="REDACT")
    p2 = store.add_policy(data_class="PHI", format="docx", route="any", action="REDACT")
    assert p1["id"] != p2["id"]
    # Persisted: a fresh store sees both.
    fresh = DocumentPolicyStore(redis_client)
    fresh_ids = {p["id"] for p in fresh.list_policies()}
    assert p1["id"] in fresh_ids and p2["id"] in fresh_ids


def test_dps_04_rejects_out_of_vocab(redis_client):
    store = DocumentPolicyStore(redis_client)
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="any", route="any", action="DROP")
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="exe", route="any", action="LOG")
    with pytest.raises(ValueError):
        store.add_policy(data_class="PII", format="any", route="moon", action="LOG")


def test_dps_05_remove(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    assert store.remove_policy("1") is True
    assert store.remove_policy("1") is False
    assert all(p["id"] != "1" for p in store.list_policies())
    # Removal persisted.
    fresh = DocumentPolicyStore(redis_client)
    assert all(p["id"] != "1" for p in fresh.list_policies())


def test_dps_06_persistence_replay(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.add_policy(data_class="IP_MARKING", format="any", route="any", action="BLOCK")
    fresh = DocumentPolicyStore(redis_client)
    assert any(p["data_class"] == "IP_MARKING" for p in fresh.list_policies())


def test_dps_07_to_opa_document_shape(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    doc = store.to_opa_document()
    assert set(doc.keys()) == {"policies", "config"}
    assert isinstance(doc["policies"], list) and len(doc["policies"]) == 5
    row = doc["policies"][0]
    # IRIS-DOC-META: policy_id / user_message / code are now included so the
    # rego can surface operator-supplied self-describing fields in the decision.
    assert set(row.keys()) == {
        "data_class", "format", "route", "action",
        "pseudonymize_mode", "small_set_escalation",
        "policy_id", "user_message", "code",
    }
    assert set(doc["config"].keys()) == {
        "detokenize_role", "map_ttl_seconds", "small_set_threshold",
    }


def test_dps_07b_to_opa_document_self_describing_fields_seeded(redis_client):
    """IRIS-DOC-META: seeded example rows carry non-empty operator fields in the
    OPA document so the rego decision can surface them."""
    store = DocumentPolicyStore(redis_client)
    store.seed_defaults()
    doc = store.to_opa_document()
    # The four example policies have self-describing fields; find PII-1.
    pii_1 = next(
        p for p in doc["policies"] if p.get("policy_id") == "DOC-EX-PII-1"
    )
    assert pii_1["policy_id"] == "DOC-EX-PII-1"
    assert pii_1["user_message"] != ""
    assert pii_1["code"] == "DOCUMENT_PII_PSEUDONYMIZED"


def test_dps_07c_to_opa_document_operator_row_empty_strings_when_unset(redis_client):
    """IRIS-DOC-META: an operator-added policy that omits self-describing fields
    gets empty-string values in the OPA document (the rego treats these as fallback
    to built-in values)."""
    store = DocumentPolicyStore(redis_client)
    # add_policy with no policy_id/user_message/code arguments.
    store.add_policy(data_class="PII", format="any", route="any", action="LOG")
    doc = store.to_opa_document()
    row = doc["policies"][0]
    assert row["policy_id"] == ""
    assert row["user_message"] == ""
    assert row["code"] == ""


def test_dps_08_config_write_through(redis_client):
    store = DocumentPolicyStore(redis_client)
    store.set_config(detokenize_role="custom-role", map_ttl_seconds=60)
    fresh = DocumentPolicyStore(redis_client)
    cfg = fresh.get_config()
    assert cfg["detokenize_role"] == "custom-role"
    assert cfg["map_ttl_seconds"] == 60
    # untouched key keeps default
    assert cfg["small_set_threshold"] == 20
